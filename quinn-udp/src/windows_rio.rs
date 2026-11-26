//! Sending and receiving through Registered I/O (RIO).
//!
//! A fixed number of receives into a registered slab stay posted at all times. [`Rio::recv`]
//! dequeues completions without a syscall, copies each datagram into the caller's buffer and
//! re-posts its slot. [`Rio::send`] copies a transmit into a free slot of a second slab and posts
//! it, with USO if the transmit holds several datagrams; its completion frees the slot again.
//!
//! Sends and receives complete on separate queues, each signalling its own event so that one
//! direction's completions never wake the other. A thread pool wait turns each event into
//! [`Waker`] calls, keeping this independent of any particular async runtime.

use std::{
    alloc::{self, Layout},
    collections::BTreeMap,
    ffi::c_void,
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr},
    os::windows::io::AsRawSocket,
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    Networking::WinSock,
    System::Threading::{
        CreateEventW, INFINITE, RegisterWaitForSingleObject, UnregisterWaitEx,
        WT_EXECUTEINWAITTHREAD,
    },
};

use super::{CMSG_LEN, decode_control, encode_control, sockaddr_inet_to_std};
use crate::{
    EcnCodepoint, RecvMeta, Transmit,
    log::{debug, info, warn},
};

const RIO_INVALID_BUFFERID: WinSock::RIO_BUFFERID = 0xFFFF_FFFF;
const RIO_INVALID_CQ: WinSock::RIO_CQ = 0;
const RIO_INVALID_RQ: WinSock::RIO_RQ = 0;

/// `RIO_CMSG_BASE_SIZE`: the control messages follow the `RIO_CMSG_BUFFER` header at this offset.
const RIO_CMSG_BASE_SIZE: usize = 8;

const ADDR_LEN: usize = size_of::<WinSock::SOCKADDR_INET>();

const STATS_INTERVAL: Duration = Duration::from_secs(5);

pub(super) struct Rio {
    recv: Mutex<RecvSide>,
    send: Mutex<SendSide>,
    /// Serializes posting to the request queue, which both sides share.
    rq: Mutex<WinSock::RIO_RQ>,
}

impl Rio {
    pub(super) fn new(
        socket: &impl AsRawSocket,
        recv_slots: usize,
        send_slots: usize,
        max_recv_size: usize,
        max_send_size: usize,
    ) -> io::Result<Self> {
        let to_u32 = |n: usize| {
            u32::try_from(n)
                .ok()
                .filter(|n| *n > 0)
                .ok_or(io::ErrorKind::InvalidInput)
        };
        let recv_slots_u32 = to_u32(recv_slots)?;
        let send_slots_u32 = to_u32(send_slots)?;

        let f = load_function_table(socket)?;

        let recv_queue = Queue::new(f, recv_slots_u32)?;
        let send_queue = Queue::new(f, send_slots_u32)?;

        let rq = unsafe {
            (f.create_rq)(
                socket.as_raw_socket() as _,
                recv_slots_u32,
                1,
                send_slots_u32,
                1,
                recv_queue.cq,
                send_queue.cq,
                ptr::null(),
            )
        };
        if rq == RIO_INVALID_RQ {
            return Err(wsa_error());
        }

        let mut recv_slab = Slab::new(recv_slots, max_recv_size)?;
        recv_slab.register(&f)?;
        let mut send_slab = Slab::new(send_slots, max_send_size)?;
        send_slab.register(&f)?;

        let this = Self {
            recv: Mutex::new(RecvSide {
                f,
                queue: recv_queue,
                slab: recv_slab,
                results: Vec::with_capacity(recv_slots),
                next_result: 0,
                stats: RecvStats::default(),
            }),
            send: Mutex::new(SendSide {
                f,
                queue: send_queue,
                slab: send_slab,
                free: (0..send_slots).rev().collect(),
                in_flight: vec![None; send_slots],
                results: Vec::with_capacity(send_slots),
                uso: true,
                stats: SendStats::default(),
            }),
            rq: Mutex::new(rq),
        };

        // Once a receive is posted the kernel may write into the slab at any time, so from here on
        // the slab must stay registered until the socket is closed: a partial failure leaves fewer
        // slots posted instead of failing.
        {
            let mut recv = this.recv.lock().unwrap();
            let rq = this.rq.lock().unwrap();
            let mut posted = 0;
            for slot in 0..recv_slots {
                match recv.post(*rq, slot) {
                    Ok(()) => posted += 1,
                    Err(e) if posted == 0 => return Err(e),
                    Err(e) => {
                        warn!("posted only {posted} of {recv_slots} RIO receives: {e}");
                        break;
                    }
                }
            }
            recv.commit(*rq)?;
        }

        Ok(this)
    }

    pub(super) fn recv(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        let mut recv = self.recv.lock().unwrap();
        if recv.next_result == recv.results.len() {
            recv.dequeue()?;
        }

        let max = bufs.len().min(meta.len());
        let mut count = 0;
        let mut repost = false;
        let rq = self.rq.lock().unwrap();
        while count < max {
            let Some(result) = recv.pop_result() else {
                break;
            };
            let slot = result.RequestContext as usize;
            repost = true;

            if result.Status != 0 {
                recv.stats.failed += 1;
                debug!(
                    "RIO receive failed: {}",
                    io::Error::from_raw_os_error(result.Status)
                );
            } else {
                match recv.read(slot, result.BytesTransferred as usize, &mut bufs[count]) {
                    Ok(m) => {
                        meta[count] = m;
                        count += 1;
                    }
                    Err(e) => debug!("dropping RIO receive: {e}"),
                }
            }

            if let Err(e) = recv.post(*rq, slot) {
                warn!("failed to re-post RIO receive: {e}");
            }
        }
        if repost {
            recv.commit(*rq)?;
        }
        drop(rq);

        recv.stats.datagrams += count as u64;
        let wakeups = recv.queue.notify.wakeups.load(Ordering::Relaxed);
        recv.stats.maybe_log(wakeups);

        match count {
            0 => Err(io::ErrorKind::WouldBlock.into()),
            n => Ok(n),
        }
    }

    /// Queues `transmit`, as a single USO request if possible, else as many of its datagrams as
    /// there are free send slots.
    pub(super) fn send(
        &self,
        transmit: &Transmit<'_>,
        ecn_v4_supported: bool,
        ecn_v6_supported: bool,
    ) -> io::Result<usize> {
        let mut send = self.send.lock().unwrap();
        send.stats.transmits += 1;
        if send.free.is_empty() {
            send.dequeue()?;
        }
        if send.free.is_empty() {
            send.stats.would_block += 1;
            return Err(io::ErrorKind::WouldBlock.into());
        }

        let len = transmit.contents.len();
        let segment_size = transmit
            .segment_size
            .filter(|s| *s != 0 && *s < len)
            .unwrap_or_else(|| len.max(1));
        let datagrams = len.div_ceil(segment_size).max(1);

        let rq = self.rq.lock().unwrap();
        let mut sent = 0;

        if send.uso && datagrams > 1 && len <= send.slab.data_len {
            let uso = Transmit {
                segment_size: Some(segment_size),
                ..transmit.clone()
            };
            match send.post(*rq, &uso, ecn_v4_supported, ecn_v6_supported) {
                Ok(()) => sent = datagrams,
                Err(e) if e.raw_os_error() == Some(WinSock::WSAEINVAL) => {
                    send.disable_uso(&e);
                }
                Err(e) => return Err(e),
            }
        }

        if sent == 0 {
            let chunks = transmit
                .contents
                .chunks(segment_size)
                .map(|contents| Transmit {
                    contents,
                    segment_size: None,
                    ..transmit.clone()
                });
            for datagram in chunks.chain(transmit.contents.is_empty().then(|| transmit.clone())) {
                if send.free.is_empty() {
                    break;
                }
                match send.post(*rq, &datagram, ecn_v4_supported, ecn_v6_supported) {
                    Ok(()) => sent += 1,
                    Err(e) if sent == 0 => return Err(e),
                    Err(_) => break,
                }
            }
        }

        send.commit(*rq)?;
        drop(rq);

        send.stats.datagrams += sent as u64;
        let wakeups = send.queue.notify.wakeups.load(Ordering::Relaxed);
        let uso = send.uso;
        send.stats.maybe_log(uso, wakeups);

        Ok(sent)
    }

    pub(super) fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut recv = self.recv.lock().unwrap();
        let recv = &mut *recv;
        let queue = &recv.queue;
        if queue.notify.take_ready() {
            return Poll::Ready(Ok(()));
        }
        queue.notify.register(cx.waker());

        if recv.next_result < recv.results.len() || recv.dequeue()? > 0 {
            return Poll::Ready(Ok(()));
        }

        recv.stats.notifies += 1;
        recv.queue.arm()?;

        // Completions that arrived before arming are not guaranteed to signal.
        if recv.dequeue()? > 0 || recv.queue.notify.take_ready() {
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }

    pub(super) fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut send = self.send.lock().unwrap();
        if send.queue.notify.take_ready() {
            return Poll::Ready(Ok(()));
        }
        send.queue.notify.register(cx.waker());

        send.dequeue()?;
        if !send.free.is_empty() {
            return Poll::Ready(Ok(()));
        }

        send.stats.notifies += 1;
        send.queue.arm()?;

        send.dequeue()?;
        if !send.free.is_empty() || send.queue.notify.take_ready() {
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }
}

impl std::fmt::Debug for Rio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rio").finish_non_exhaustive()
    }
}

struct RecvSide {
    f: Functions,
    queue: Queue,
    slab: Slab,
    /// Dequeued completions, consumed from `next_result` on.
    results: Vec<WinSock::RIORESULT>,
    next_result: usize,
    stats: RecvStats,
}

// SAFETY: the RIO handles and the slab are only accessed behind the `Mutex` in `Rio`.
unsafe impl Send for RecvSide {}

impl RecvSide {
    fn post(&mut self, rq: WinSock::RIO_RQ, slot: usize) -> io::Result<()> {
        let [data, addr, control] = self
            .slab
            .rio_bufs(slot, self.slab.data_len, CMSG_LEN as u32);
        let rc = unsafe {
            (self.f.receive_ex)(
                rq,
                &data,
                1,
                ptr::null(),
                &addr,
                &control,
                ptr::null(),
                WinSock::RIO_MSG_DEFER,
                slot as *const c_void,
            )
        };

        match rc {
            0 => Err(wsa_error()),
            _ => Ok(()),
        }
    }

    fn commit(&mut self, rq: WinSock::RIO_RQ) -> io::Result<()> {
        self.stats.commits += 1;
        let rc = unsafe {
            (self.f.receive_ex)(
                rq,
                ptr::null(),
                0,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                WinSock::RIO_MSG_COMMIT_ONLY,
                ptr::null(),
            )
        };

        match rc {
            0 => Err(wsa_error()),
            _ => Ok(()),
        }
    }

    /// Refills `results` from the completion queue, if it is exhausted.
    fn dequeue(&mut self) -> io::Result<usize> {
        if self.next_result < self.results.len() {
            return Ok(self.results.len() - self.next_result);
        }

        self.next_result = 0;
        let n = self.queue.dequeue(&mut self.results)?;
        self.stats.dequeues += 1;
        if n == 0 {
            self.stats.empty_dequeues += 1;
        }

        Ok(n)
    }

    fn pop_result(&mut self) -> Option<WinSock::RIORESULT> {
        let result = self.results.get(self.next_result).copied()?;
        self.next_result += 1;

        Some(result)
    }

    fn read(&self, slot: usize, len: usize, buf: &mut [u8]) -> io::Result<RecvMeta> {
        let slab = &self.slab;
        if len > buf.len() || len > slab.data_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("datagram of {len} bytes does not fit"),
            ));
        }

        let base = slab.slot_ptr(slot);
        // SAFETY: the slot's receive has completed, so the kernel no longer writes to it until it
        // is re-posted; `len` was checked against both buffers above.
        unsafe { ptr::copy_nonoverlapping(base, buf.as_mut_ptr(), len) };

        let addr = unsafe {
            ptr::read_unaligned(base.add(slab.addr_offset).cast::<WinSock::SOCKADDR_INET>())
        };
        let addr = sockaddr_inet_to_std(&addr)?;

        let control = unsafe { base.add(slab.control_offset) };
        let total = unsafe { ptr::read_unaligned(control.cast::<u32>()) } as usize;
        let control_len = total.clamp(RIO_CMSG_BASE_SIZE, CMSG_LEN) - RIO_CMSG_BASE_SIZE;
        let wsa_msg = WinSock::WSAMSG {
            name: ptr::null_mut(),
            namelen: 0,
            lpBuffers: ptr::null_mut(),
            dwBufferCount: 0,
            Control: WinSock::WSABUF {
                len: control_len as u32,
                buf: unsafe { control.add(RIO_CMSG_BASE_SIZE) },
            },
            dwFlags: 0,
        };
        // SAFETY: the control buffer is 8-byte aligned and bounded by the length the kernel wrote.
        let control = unsafe { decode_control(&wsa_msg) };

        Ok(RecvMeta {
            addr,
            len,
            stride: len,
            ecn: EcnCodepoint::from_bits(control.ecn_bits as u8),
            dst_ip: control.dst_ip,
            interface_index: control.interface_index,
            timestamp: None,
        })
    }
}

/// What a posted send carried, for reporting its failure.
#[derive(Clone, Copy)]
struct InFlight {
    destination: SocketAddr,
    src_ip: Option<IpAddr>,
    len: usize,
    segment_size: Option<usize>,
}

struct SendSide {
    f: Functions,
    queue: Queue,
    slab: Slab,
    free: Vec<usize>,
    in_flight: Vec<Option<InFlight>>,
    results: Vec<WinSock::RIORESULT>,
    uso: bool,
    stats: SendStats,
}

// SAFETY: the RIO handles and the slab are only accessed behind the `Mutex` in `Rio`.
unsafe impl Send for SendSide {}

impl SendSide {
    /// Posts `transmit` from a free slot, which the caller has checked exists.
    fn post(
        &mut self,
        rq: WinSock::RIO_RQ,
        transmit: &Transmit<'_>,
        ecn_v4_supported: bool,
        ecn_v6_supported: bool,
    ) -> io::Result<()> {
        let slab = &self.slab;
        let len = transmit.contents.len();
        if len > slab.data_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("datagram of {len} bytes exceeds the RIO send slot"),
            ));
        }
        let Some(&slot) = self.free.last() else {
            return Err(io::ErrorKind::WouldBlock.into());
        };

        let base = slab.slot_ptr(slot);
        let daddr = socket2::SockAddr::from(transmit.destination);
        let control = unsafe { base.add(slab.control_offset) };
        let mut wsa_msg = WinSock::WSAMSG {
            name: ptr::null_mut(),
            namelen: 0,
            lpBuffers: ptr::null_mut(),
            dwBufferCount: 0,
            Control: WinSock::WSABUF {
                len: (CMSG_LEN - RIO_CMSG_BASE_SIZE) as u32,
                buf: unsafe { control.add(RIO_CMSG_BASE_SIZE) },
            },
            dwFlags: 0,
        };

        // SAFETY: the slot is free, so the kernel does not access it; all writes stay within the
        // slot's data, address and control regions, and the control buffer is 8-byte aligned.
        unsafe {
            ptr::copy_nonoverlapping(transmit.contents.as_ptr(), base, len);
            ptr::write_bytes(base.add(slab.addr_offset), 0, ADDR_LEN);
            ptr::copy_nonoverlapping(
                daddr.as_ptr().cast::<u8>(),
                base.add(slab.addr_offset),
                (daddr.len() as usize).min(ADDR_LEN),
            );
            encode_control(&mut wsa_msg, transmit, ecn_v4_supported, ecn_v6_supported)?;
        }
        let control_len = RIO_CMSG_BASE_SIZE as u32 + wsa_msg.Control.len;
        unsafe { ptr::write_unaligned(control.cast::<u32>(), control_len) };

        let [data, addr, control] = slab.rio_bufs(slot, len, control_len);
        let rc = unsafe {
            (self.f.send_ex)(
                rq,
                &data,
                1,
                ptr::null(),
                &addr,
                &control,
                ptr::null(),
                WinSock::RIO_MSG_DEFER,
                slot as *const c_void,
            )
        };
        if rc == 0 {
            return Err(wsa_error());
        }

        self.free.pop();
        self.in_flight[slot] = Some(InFlight {
            destination: transmit.destination,
            src_ip: transmit.src_ip,
            len,
            segment_size: transmit.segment_size,
        });
        self.stats.requests += 1;

        Ok(())
    }

    fn commit(&mut self, rq: WinSock::RIO_RQ) -> io::Result<()> {
        self.stats.commits += 1;
        let rc = unsafe {
            (self.f.send_ex)(
                rq,
                ptr::null(),
                0,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                WinSock::RIO_MSG_COMMIT_ONLY,
                ptr::null(),
            )
        };

        match rc {
            0 => Err(wsa_error()),
            _ => Ok(()),
        }
    }

    /// Frees the slots of all completed sends.
    fn dequeue(&mut self) -> io::Result<()> {
        let n = self.queue.dequeue(&mut self.results)?;
        self.stats.dequeues += 1;
        self.stats.completions += n as u64;

        for i in 0..n {
            let result = self.results[i];
            let slot = result.RequestContext as usize;
            self.free.push(slot);
            let in_flight = self.in_flight[slot].take();

            if result.Status == 0 {
                continue;
            }

            let error = io::Error::from_raw_os_error(result.Status);
            let count = self.stats.errors.entry(result.Status).or_default();
            *count += 1;
            if *count <= 4 || count.is_power_of_two() {
                warn!(
                    "RIO send failed ({count} so far): {error}; destination={:?} src_ip={:?} len={:?} segment_size={:?}",
                    in_flight.map(|f| f.destination),
                    in_flight.and_then(|f| f.src_ip),
                    in_flight.map(|f| f.len),
                    in_flight.and_then(|f| f.segment_size),
                );
            }
            if result.Status == WinSock::WSAEINVAL
                && in_flight.is_some_and(|f| f.segment_size.is_some())
            {
                self.disable_uso(&error);
            }
        }

        Ok(())
    }

    fn disable_uso(&mut self, error: &io::Error) {
        if self.uso {
            warn!("RIO rejected USO, sending datagrams individually: {error}");
            self.uso = false;
        }
    }
}

/// A completion queue that signals an event, turned into [`Waker`] calls by a thread pool wait.
struct Queue {
    f: Functions,
    cq: WinSock::RIO_CQ,
    event: HANDLE,
    wait: HANDLE,
    /// The `Arc<Notify>` reference owned by the thread pool wait.
    wait_context: *const Notify,
    notify: Arc<Notify>,
}

impl Queue {
    fn new(f: Functions, size: u32) -> io::Result<Self> {
        let mut this = Self {
            f,
            cq: RIO_INVALID_CQ,
            event: ptr::null_mut(),
            wait: ptr::null_mut(),
            wait_context: ptr::null(),
            notify: Arc::new(Notify::default()),
        };

        // Auto-reset, as the thread pool wait consumes each signal.
        this.event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if this.event.is_null() {
            return Err(io::Error::last_os_error());
        }

        let notification = WinSock::RIO_NOTIFICATION_COMPLETION {
            Type: WinSock::RIO_EVENT_COMPLETION,
            Anonymous: WinSock::RIO_NOTIFICATION_COMPLETION_0 {
                Event: WinSock::RIO_NOTIFICATION_COMPLETION_0_0 {
                    EventHandle: this.event,
                    NotifyReset: 0,
                },
            },
        };
        this.cq = unsafe { (f.create_cq)(size, &notification) };
        if this.cq == RIO_INVALID_CQ {
            return Err(wsa_error());
        }

        let wait_context = Arc::into_raw(this.notify.clone());
        let rc = unsafe {
            RegisterWaitForSingleObject(
                &mut this.wait,
                this.event,
                Some(on_event),
                wait_context.cast(),
                INFINITE,
                WT_EXECUTEINWAITTHREAD,
            )
        };
        if rc == 0 {
            let error = io::Error::last_os_error();
            drop(unsafe { Arc::from_raw(wait_context) });
            return Err(error);
        }
        this.wait_context = wait_context;

        Ok(this)
    }

    fn arm(&self) -> io::Result<()> {
        let rc = unsafe { (self.f.notify)(self.cq) };
        if rc != 0 && rc != WinSock::WSAEALREADY {
            return Err(io::Error::from_raw_os_error(rc));
        }

        Ok(())
    }

    fn dequeue(&self, results: &mut Vec<WinSock::RIORESULT>) -> io::Result<usize> {
        results.clear();
        let n =
            unsafe { (self.f.dequeue)(self.cq, results.as_mut_ptr(), results.capacity() as u32) };
        if n == WinSock::RIO_CORRUPT_CQ {
            return Err(io::Error::other("RIO completion queue is corrupt"));
        }
        // SAFETY: `RIODequeueCompletion` initialized `n <= capacity` entries.
        unsafe { results.set_len(n as usize) };

        Ok(n as usize)
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        unsafe {
            if !self.wait.is_null() {
                // Blocks until a running callback has returned.
                UnregisterWaitEx(self.wait, INVALID_HANDLE_VALUE);
                drop(Arc::from_raw(self.wait_context));
            }
            if self.cq != RIO_INVALID_CQ {
                (self.f.close_cq)(self.cq);
            }
            if !self.event.is_null() {
                CloseHandle(self.event);
            }
        }
    }
}

#[derive(Default)]
struct Notify {
    ready: AtomicBool,
    wakeups: AtomicU64,
    waker: Mutex<Option<Waker>>,
}

impl Notify {
    fn take_ready(&self) -> bool {
        self.ready.swap(false, Ordering::Acquire)
    }

    fn register(&self, waker: &Waker) {
        let mut stored = self.waker.lock().unwrap();
        match &*stored {
            Some(w) if w.will_wake(waker) => {}
            _ => *stored = Some(waker.clone()),
        }
    }
}

unsafe extern "system" fn on_event(context: *mut c_void, _timed_out: bool) {
    let notify = unsafe { &*context.cast::<Notify>() };
    notify.wakeups.fetch_add(1, Ordering::Relaxed);
    notify.ready.store(true, Ordering::Release);

    let waker = notify.waker.lock().unwrap().take();
    if let Some(waker) = waker {
        waker.wake();
    }
}

struct RecvStats {
    since: Instant,
    dequeues: u64,
    empty_dequeues: u64,
    datagrams: u64,
    failed: u64,
    notifies: u64,
    commits: u64,
    wakeups_before: u64,
}

impl Default for RecvStats {
    fn default() -> Self {
        Self {
            since: Instant::now(),
            dequeues: 0,
            empty_dequeues: 0,
            datagrams: 0,
            failed: 0,
            notifies: 0,
            commits: 0,
            wakeups_before: 0,
        }
    }
}

impl RecvStats {
    fn maybe_log(&mut self, wakeups: u64) {
        if self.since.elapsed() < STATS_INTERVAL {
            return;
        }

        let full = self.dequeues - self.empty_dequeues;
        info!(
            "RIO recv stats over {:?}: dequeues={} empty_dequeues={} datagrams={} per_dequeue={:.1} failed={} notifies={} wakeups={} commits={}",
            self.since.elapsed(),
            self.dequeues,
            self.empty_dequeues,
            self.datagrams,
            self.datagrams as f64 / full.max(1) as f64,
            self.failed,
            self.notifies,
            wakeups - self.wakeups_before,
            self.commits,
        );
        *self = Self {
            wakeups_before: wakeups,
            ..Self::default()
        };
    }
}

struct SendStats {
    since: Instant,
    transmits: u64,
    requests: u64,
    datagrams: u64,
    commits: u64,
    dequeues: u64,
    completions: u64,
    would_block: u64,
    notifies: u64,
    wakeups_before: u64,
    errors: BTreeMap<i32, u64>,
}

impl Default for SendStats {
    fn default() -> Self {
        Self {
            since: Instant::now(),
            transmits: 0,
            requests: 0,
            datagrams: 0,
            commits: 0,
            dequeues: 0,
            completions: 0,
            would_block: 0,
            notifies: 0,
            wakeups_before: 0,
            errors: BTreeMap::new(),
        }
    }
}

impl SendStats {
    fn maybe_log(&mut self, uso: bool, wakeups: u64) {
        if self.since.elapsed() < STATS_INTERVAL {
            return;
        }

        info!(
            "RIO send stats over {:?}: uso={uso} transmits={} requests={} datagrams={} commits={} dequeues={} completions={} would_block={} notifies={} wakeups={} errors={:?}",
            self.since.elapsed(),
            self.transmits,
            self.requests,
            self.datagrams,
            self.commits,
            self.dequeues,
            self.completions,
            self.would_block,
            self.notifies,
            wakeups - self.wakeups_before,
            self.errors,
        );
        *self = Self {
            wakeups_before: wakeups,
            ..Self::default()
        };
    }
}

type RioBufPtr = *const WinSock::RIO_BUF;

#[derive(Clone, Copy)]
struct Functions {
    create_cq: unsafe extern "system" fn(
        u32,
        *const WinSock::RIO_NOTIFICATION_COMPLETION,
    ) -> WinSock::RIO_CQ,
    create_rq: unsafe extern "system" fn(
        WinSock::SOCKET,
        u32,
        u32,
        u32,
        u32,
        WinSock::RIO_CQ,
        WinSock::RIO_CQ,
        *const c_void,
    ) -> WinSock::RIO_RQ,
    register_buffer: unsafe extern "system" fn(*const u8, u32) -> WinSock::RIO_BUFFERID,
    deregister_buffer: unsafe extern "system" fn(WinSock::RIO_BUFFERID),
    close_cq: unsafe extern "system" fn(WinSock::RIO_CQ),
    receive_ex: unsafe extern "system" fn(
        WinSock::RIO_RQ,
        RioBufPtr,
        u32,
        RioBufPtr,
        RioBufPtr,
        RioBufPtr,
        RioBufPtr,
        u32,
        *const c_void,
    ) -> i32,
    send_ex: unsafe extern "system" fn(
        WinSock::RIO_RQ,
        RioBufPtr,
        u32,
        RioBufPtr,
        RioBufPtr,
        RioBufPtr,
        RioBufPtr,
        u32,
        *const c_void,
    ) -> i32,
    dequeue: unsafe extern "system" fn(WinSock::RIO_CQ, *mut WinSock::RIORESULT, u32) -> u32,
    notify: unsafe extern "system" fn(WinSock::RIO_CQ) -> i32,
}

fn load_function_table(socket: &impl AsRawSocket) -> io::Result<Functions> {
    let guid = WinSock::WSAID_MULTIPLE_RIO;
    let mut table = WinSock::RIO_EXTENSION_FUNCTION_TABLE {
        cbSize: size_of::<WinSock::RIO_EXTENSION_FUNCTION_TABLE>() as u32,
        ..Default::default()
    };
    let mut len = 0;

    let rc = unsafe {
        WinSock::WSAIoctl(
            socket.as_raw_socket() as _,
            WinSock::SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
            &guid as *const _ as *const _,
            size_of_val(&guid) as u32,
            &mut table as *mut _ as *mut _,
            size_of_val(&table) as u32,
            &mut len,
            ptr::null_mut(),
            None,
        )
    };
    if rc != 0 {
        return Err(wsa_error());
    }

    let missing = || io::Error::new(io::ErrorKind::Unsupported, "incomplete RIO function table");

    Ok(Functions {
        create_cq: table.RIOCreateCompletionQueue.ok_or_else(missing)?,
        create_rq: table.RIOCreateRequestQueue.ok_or_else(missing)?,
        register_buffer: table.RIORegisterBuffer.ok_or_else(missing)?,
        deregister_buffer: table.RIODeregisterBuffer.ok_or_else(missing)?,
        close_cq: table.RIOCloseCompletionQueue.ok_or_else(missing)?,
        receive_ex: table.RIOReceiveEx.ok_or_else(missing)?,
        send_ex: table.RIOSendEx.ok_or_else(missing)?,
        dequeue: table.RIODequeueCompletion.ok_or_else(missing)?,
        notify: table.RIONotify.ok_or_else(missing)?,
    })
}

/// Registered memory: per slot, a datagram, its remote address and its control messages.
struct Slab {
    ptr: *mut u8,
    layout: Layout,
    buffer_id: WinSock::RIO_BUFFERID,
    deregister: Option<unsafe extern "system" fn(WinSock::RIO_BUFFERID)>,
    slot_len: usize,
    data_len: usize,
    addr_offset: usize,
    control_offset: usize,
}

impl Slab {
    fn new(slots: usize, max_datagram_size: usize) -> io::Result<Self> {
        let align8 = |n: usize| n.next_multiple_of(8);
        let addr_offset = align8(max_datagram_size);
        let control_offset = addr_offset + align8(ADDR_LEN);
        let slot_len = control_offset + CMSG_LEN;

        let size = slot_len
            .checked_mul(slots)
            .filter(|s| u32::try_from(*s).is_ok())
            .ok_or(io::ErrorKind::InvalidInput)?;
        let layout = Layout::from_size_align(size, 4096)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let ptr = unsafe { alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }

        Ok(Self {
            ptr,
            layout,
            buffer_id: RIO_INVALID_BUFFERID,
            deregister: None,
            slot_len,
            data_len: max_datagram_size,
            addr_offset,
            control_offset,
        })
    }

    fn register(&mut self, f: &Functions) -> io::Result<()> {
        self.buffer_id = unsafe { (f.register_buffer)(self.ptr, self.layout.size() as u32) };
        if self.buffer_id == RIO_INVALID_BUFFERID {
            return Err(wsa_error());
        }
        self.deregister = Some(f.deregister_buffer);

        Ok(())
    }

    fn slot_ptr(&self, slot: usize) -> *mut u8 {
        assert!(slot * self.slot_len < self.layout.size());
        unsafe { self.ptr.add(slot * self.slot_len) }
    }

    fn rio_bufs(&self, slot: usize, data_len: usize, control_len: u32) -> [WinSock::RIO_BUF; 3] {
        let offset = (slot * self.slot_len) as u32;
        let buf = |start: usize, len: u32| WinSock::RIO_BUF {
            BufferId: self.buffer_id,
            Offset: offset + start as u32,
            Length: len,
        };

        [
            buf(0, data_len as u32),
            buf(self.addr_offset, ADDR_LEN as u32),
            buf(self.control_offset, control_len),
        ]
    }
}

impl Drop for Slab {
    fn drop(&mut self) {
        unsafe {
            if let Some(deregister) = self.deregister {
                deregister(self.buffer_id);
            }
            alloc::dealloc(self.ptr, self.layout);
        }
    }
}

fn wsa_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { WinSock::WSAGetLastError() })
}
