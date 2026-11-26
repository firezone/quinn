//! Sending and receiving through Registered I/O (RIO).
//!
//! A fixed number of receives into a registered slab stay posted at all times. [`Rio::recv`]
//! dequeues completions without a syscall, copies each datagram into the caller's buffer and
//! re-posts its slot. [`Rio::send`] copies each datagram into a free slot of a second slab and
//! posts it; its completion frees the slot again. Sends and receives share one completion queue,
//! told apart by the request context.
//!
//! Readiness comes from `RIONotify` signalling an event, which a thread pool wait turns into
//! [`Waker`] calls, keeping this independent of any particular async runtime.

use std::{
    alloc::{self, Layout},
    collections::VecDeque,
    ffi::c_void,
    io::{self, IoSliceMut},
    os::windows::io::AsRawSocket,
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
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
    log::{debug, warn},
};

const RIO_INVALID_BUFFERID: WinSock::RIO_BUFFERID = 0xFFFF_FFFF;
const RIO_INVALID_CQ: WinSock::RIO_CQ = 0;
const RIO_INVALID_RQ: WinSock::RIO_RQ = 0;

/// `RIO_CMSG_BASE_SIZE`: the control messages follow the `RIO_CMSG_BUFFER` header at this offset.
const RIO_CMSG_BASE_SIZE: usize = 8;

const ADDR_LEN: usize = size_of::<WinSock::SOCKADDR_INET>();

/// Marks the request context of a send; receives use the bare slot index.
const SEND_BIT: usize = 1 << (usize::BITS - 1);

pub(super) struct Rio {
    inner: Mutex<Inner>,
    signal: Arc<Signal>,
    wait: HANDLE,
    /// The `Arc<Signal>` reference owned by the thread pool wait.
    wait_context: *const Signal,
}

// SAFETY: `wait` and `wait_context` are only used on drop, after the wait is unregistered.
unsafe impl Send for Rio {}
unsafe impl Sync for Rio {}

impl Rio {
    pub(super) fn new(
        socket: &impl AsRawSocket,
        recv_slots: usize,
        send_slots: usize,
        max_datagram_size: usize,
    ) -> io::Result<Self> {
        let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
        let to_u32 = |n: usize| u32::try_from(n).ok().filter(|n| *n > 0).ok_or_else(invalid);
        let recv_slots_u32 = to_u32(recv_slots)?;
        let send_slots_u32 = to_u32(send_slots)?;

        let rio = load_function_table(socket)?;

        let mut inner = Inner {
            rio,
            event: ptr::null_mut(),
            cq: RIO_INVALID_CQ,
            rq: RIO_INVALID_RQ,
            recv_slab: Slab::new(recv_slots, max_datagram_size)?,
            send_slab: Slab::new(send_slots, max_datagram_size)?,
            recv_results: VecDeque::with_capacity(recv_slots),
            scratch: Vec::with_capacity(recv_slots + send_slots),
            free_send: (0..send_slots).rev().collect(),
            send_errors: 0,
        };

        // Auto-reset, as the thread pool wait consumes each signal.
        inner.event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if inner.event.is_null() {
            return Err(io::Error::last_os_error());
        }

        let notification = WinSock::RIO_NOTIFICATION_COMPLETION {
            Type: WinSock::RIO_EVENT_COMPLETION,
            Anonymous: WinSock::RIO_NOTIFICATION_COMPLETION_0 {
                Event: WinSock::RIO_NOTIFICATION_COMPLETION_0_0 {
                    EventHandle: inner.event,
                    NotifyReset: 0,
                },
            },
        };
        inner.cq = unsafe { (inner.rio.create_cq)(recv_slots_u32 + send_slots_u32, &notification) };
        if inner.cq == RIO_INVALID_CQ {
            return Err(wsa_error());
        }

        inner.rq = unsafe {
            (inner.rio.create_rq)(
                socket.as_raw_socket() as _,
                recv_slots_u32,
                1,
                send_slots_u32,
                1,
                inner.cq,
                inner.cq,
                ptr::null(),
            )
        };
        if inner.rq == RIO_INVALID_RQ {
            return Err(wsa_error());
        }

        inner.recv_slab.register(&inner.rio)?;
        inner.send_slab.register(&inner.rio)?;

        let signal = Arc::new(Signal::default());
        let wait_context = Arc::into_raw(signal.clone());
        let mut wait = ptr::null_mut();
        let rc = unsafe {
            RegisterWaitForSingleObject(
                &mut wait,
                inner.event,
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

        let this = Self {
            inner: Mutex::new(inner),
            signal,
            wait,
            wait_context,
        };

        // Once a receive is posted the kernel may write into the slab at any time, so from here on
        // the slab must stay registered until the socket is closed: a partial failure leaves fewer
        // slots posted instead of failing.
        {
            let mut inner = this.inner.lock().unwrap();
            let mut posted = 0;
            for slot in 0..recv_slots {
                match inner.post_recv(slot) {
                    Ok(()) => posted += 1,
                    Err(e) if posted == 0 => return Err(e),
                    Err(e) => {
                        warn!("posted only {posted} of {recv_slots} RIO receives: {e}");
                        break;
                    }
                }
            }
            inner.commit_recv()?;
        }

        Ok(this)
    }

    pub(super) fn recv(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        if inner.recv_results.is_empty() {
            inner.drain()?;
        }

        let max = bufs.len().min(meta.len());
        let mut count = 0;
        while count < max {
            let Some(result) = inner.recv_results.pop_front() else {
                break;
            };
            let slot = result.RequestContext as usize;

            if result.Status != 0 {
                debug!(
                    "RIO receive failed: {}",
                    io::Error::from_raw_os_error(result.Status)
                );
            } else {
                match inner.read(slot, result.BytesTransferred as usize, &mut bufs[count]) {
                    Ok(m) => {
                        meta[count] = m;
                        count += 1;
                    }
                    Err(e) => debug!("dropping RIO receive: {e}"),
                }
            }

            if let Err(e) = inner.post_recv(slot) {
                warn!("failed to re-post RIO receive: {e}");
            }
        }
        inner.commit_recv()?;

        match count {
            0 => Err(io::ErrorKind::WouldBlock.into()),
            n => Ok(n),
        }
    }

    /// Queues as many datagrams of `transmit` as there are free send slots.
    pub(super) fn send(
        &self,
        transmit: &Transmit<'_>,
        ecn_v4_supported: bool,
        ecn_v6_supported: bool,
    ) -> io::Result<usize> {
        let segment_size = match transmit.segment_size {
            Some(s) if s != 0 => s,
            _ => transmit.contents.len().max(1),
        };

        let mut inner = self.inner.lock().unwrap();
        if inner.free_send.is_empty() {
            inner.drain()?;
        }

        let mut count = 0;
        for contents in transmit.contents.chunks(segment_size.max(1)) {
            let Some(slot) = inner.free_send.pop() else {
                break;
            };

            let datagram = Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents,
                segment_size: None,
                src_ip: transmit.src_ip,
            };

            match inner.post_send(slot, &datagram, ecn_v4_supported, ecn_v6_supported) {
                Ok(()) => count += 1,
                Err(e) => {
                    inner.free_send.push(slot);
                    if count == 0 {
                        return Err(e);
                    }
                    break;
                }
            }
        }
        // An empty transmit is a single empty datagram.
        if transmit.contents.is_empty()
            && let Some(slot) = inner.free_send.pop()
        {
            match inner.post_send(slot, transmit, ecn_v4_supported, ecn_v6_supported) {
                Ok(()) => count = 1,
                Err(e) => {
                    inner.free_send.push(slot);
                    return Err(e);
                }
            }
        }

        if count == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        inner.commit_send()?;

        Ok(count)
    }

    pub(super) fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_ready(cx, &self.signal.recv, |inner| {
            !inner.recv_results.is_empty()
        })
    }

    pub(super) fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_ready(cx, &self.signal.send, |inner| !inner.free_send.is_empty())
    }

    fn poll_ready(
        &self,
        cx: &mut Context<'_>,
        notify: &Notify,
        is_ready: impl Fn(&Inner) -> bool,
    ) -> Poll<io::Result<()>> {
        if notify.take_ready() {
            return Poll::Ready(Ok(()));
        }
        notify.register(cx.waker());

        let mut inner = self.inner.lock().unwrap();
        if is_ready(&inner) {
            return Poll::Ready(Ok(()));
        }

        let rc = unsafe { (inner.rio.notify)(inner.cq) };
        if rc != 0 && rc != WinSock::WSAEALREADY {
            return Poll::Ready(Err(io::Error::from_raw_os_error(rc)));
        }

        // Completions that arrived before arming are not guaranteed to signal.
        inner.drain()?;
        if is_ready(&inner) || notify.take_ready() {
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }
}

impl Drop for Rio {
    fn drop(&mut self) {
        // Blocks until a running callback has returned.
        unsafe { UnregisterWaitEx(self.wait, INVALID_HANDLE_VALUE) };
        drop(unsafe { Arc::from_raw(self.wait_context) });
    }
}

impl std::fmt::Debug for Rio {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rio").finish_non_exhaustive()
    }
}

#[derive(Default)]
struct Signal {
    recv: Notify,
    send: Notify,
}

#[derive(Default)]
struct Notify {
    ready: AtomicBool,
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

    fn wake(&self) {
        self.ready.store(true, Ordering::Release);

        let waker = self.waker.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

unsafe extern "system" fn on_event(context: *mut c_void, _timed_out: bool) {
    let signal = unsafe { &*context.cast::<Signal>() };
    signal.recv.wake();
    signal.send.wake();
}

type RioBufPtr = *const WinSock::RIO_BUF;

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

struct Inner {
    rio: Functions,
    event: HANDLE,
    cq: WinSock::RIO_CQ,
    rq: WinSock::RIO_RQ,
    recv_slab: Slab,
    send_slab: Slab,
    /// Completed receives, dequeued but not yet handed out.
    recv_results: VecDeque<WinSock::RIORESULT>,
    scratch: Vec<WinSock::RIORESULT>,
    free_send: Vec<usize>,
    send_errors: u64,
}

// SAFETY: the RIO handles and the slabs are only accessed behind the `Mutex` in `Rio`.
unsafe impl Send for Inner {}

impl Inner {
    fn post_recv(&mut self, slot: usize) -> io::Result<()> {
        let slab = &self.recv_slab;
        let [data, addr, control] = slab.rio_bufs(slot, slab.data_len, CMSG_LEN as u32);
        let rc = unsafe {
            (self.rio.receive_ex)(
                self.rq,
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

    fn commit_recv(&mut self) -> io::Result<()> {
        let rc = unsafe {
            (self.rio.receive_ex)(
                self.rq,
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

    fn post_send(
        &mut self,
        slot: usize,
        datagram: &Transmit<'_>,
        ecn_v4_supported: bool,
        ecn_v6_supported: bool,
    ) -> io::Result<()> {
        let slab = &self.send_slab;
        let len = datagram.contents.len();
        if len > slab.data_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("datagram of {len} bytes exceeds the RIO send slot"),
            ));
        }

        let base = slab.slot_ptr(slot);
        let daddr = socket2::SockAddr::from(datagram.destination);
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
            ptr::copy_nonoverlapping(datagram.contents.as_ptr(), base, len);
            ptr::write_bytes(base.add(slab.addr_offset), 0, ADDR_LEN);
            ptr::copy_nonoverlapping(
                daddr.as_ptr().cast::<u8>(),
                base.add(slab.addr_offset),
                (daddr.len() as usize).min(ADDR_LEN),
            );
            encode_control(&mut wsa_msg, datagram, ecn_v4_supported, ecn_v6_supported)?;
        }
        let control_len = RIO_CMSG_BASE_SIZE as u32 + wsa_msg.Control.len;
        unsafe { ptr::write_unaligned(control.cast::<u32>(), control_len) };

        let [data, addr, control] = slab.rio_bufs(slot, len, control_len);
        let rc = unsafe {
            (self.rio.send_ex)(
                self.rq,
                &data,
                1,
                ptr::null(),
                &addr,
                &control,
                ptr::null(),
                WinSock::RIO_MSG_DEFER,
                (slot | SEND_BIT) as *const c_void,
            )
        };

        match rc {
            0 => Err(wsa_error()),
            _ => Ok(()),
        }
    }

    fn commit_send(&mut self) -> io::Result<()> {
        let rc = unsafe {
            (self.rio.send_ex)(
                self.rq,
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

    /// Dequeues all completions: sends free their slots, receives are queued for [`Rio::recv`].
    fn drain(&mut self) -> io::Result<()> {
        self.scratch.clear();
        let n = unsafe {
            (self.rio.dequeue)(
                self.cq,
                self.scratch.as_mut_ptr(),
                self.scratch.capacity() as u32,
            )
        };
        if n == WinSock::RIO_CORRUPT_CQ {
            return Err(io::Error::other("RIO completion queue is corrupt"));
        }
        // SAFETY: `RIODequeueCompletion` initialized `n <= capacity` entries.
        unsafe { self.scratch.set_len(n as usize) };

        for result in self.scratch.drain(..) {
            let context = result.RequestContext as usize;
            if context & SEND_BIT == 0 {
                self.recv_results.push_back(result);
                continue;
            }

            self.free_send.push(context & !SEND_BIT);
            if result.Status != 0 {
                self.send_errors += 1;
                if self.send_errors.is_power_of_two() {
                    warn!(
                        "RIO send failed ({} so far): {}",
                        self.send_errors,
                        io::Error::from_raw_os_error(result.Status)
                    );
                }
            }
        }

        Ok(())
    }

    fn read(&self, slot: usize, len: usize, buf: &mut [u8]) -> io::Result<RecvMeta> {
        let slab = &self.recv_slab;
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

impl Drop for Inner {
    fn drop(&mut self) {
        // The request queue has no close function: it is freed with the socket.
        unsafe {
            if self.cq != RIO_INVALID_CQ {
                (self.rio.close_cq)(self.cq);
            }
            for slab in [&self.recv_slab, &self.send_slab] {
                if slab.buffer_id != RIO_INVALID_BUFFERID {
                    (self.rio.deregister_buffer)(slab.buffer_id);
                }
            }
            if !self.event.is_null() {
                CloseHandle(self.event);
            }
        }
    }
}

/// Registered memory: per slot, a datagram, its remote address and its control messages.
struct Slab {
    ptr: *mut u8,
    layout: Layout,
    buffer_id: WinSock::RIO_BUFFERID,
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
            slot_len,
            data_len: max_datagram_size,
            addr_offset,
            control_offset,
        })
    }

    fn register(&mut self, rio: &Functions) -> io::Result<()> {
        self.buffer_id = unsafe { (rio.register_buffer)(self.ptr, self.layout.size() as u32) };
        if self.buffer_id == RIO_INVALID_BUFFERID {
            return Err(wsa_error());
        }

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
        unsafe { alloc::dealloc(self.ptr, self.layout) };
    }
}

fn wsa_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { WinSock::WSAGetLastError() })
}
