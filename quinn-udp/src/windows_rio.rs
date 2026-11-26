//! Receiving through Registered I/O (RIO).
//!
//! A fixed number of receives into one registered slab stay posted at all times. [`RioRecv::recv`]
//! dequeues completions without a syscall, copies each datagram into the caller's buffer and
//! re-posts its slot. Readiness comes from `RIONotify` signalling an event, which a thread pool wait
//! turns into a [`Waker`] call, keeping this independent of any particular async runtime.

use std::{
    alloc::{self, Layout},
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

use super::{CMSG_LEN, decode_control, sockaddr_inet_to_std};
use crate::{EcnCodepoint, RecvMeta, log::debug};

const RIO_INVALID_BUFFERID: WinSock::RIO_BUFFERID = 0xFFFF_FFFF;
const RIO_INVALID_CQ: WinSock::RIO_CQ = 0;
const RIO_INVALID_RQ: WinSock::RIO_RQ = 0;

/// `RIO_CMSG_BASE_SIZE`: the control messages follow the `RIO_CMSG_BUFFER` header at this offset.
const RIO_CMSG_BASE_SIZE: usize = 8;

const ADDR_LEN: usize = size_of::<WinSock::SOCKADDR_INET>();

pub(super) struct RioRecv {
    inner: Mutex<Inner>,
    signal: Arc<Signal>,
    wait: HANDLE,
    /// The `Arc<Signal>` reference owned by the thread pool wait.
    wait_context: *const Signal,
}

// SAFETY: `wait` and `wait_context` are only used on drop, after the wait is unregistered.
unsafe impl Send for RioRecv {}
unsafe impl Sync for RioRecv {}

impl RioRecv {
    pub(super) fn new(
        socket: &impl AsRawSocket,
        slots: usize,
        max_datagram_size: usize,
    ) -> io::Result<Self> {
        let slots = u32::try_from(slots)
            .ok()
            .filter(|s| *s > 0)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let rio = load_function_table(socket)?;
        let slab = Slab::new(slots as usize, max_datagram_size)?;

        let mut inner = Inner {
            rio,
            event: ptr::null_mut(),
            cq: RIO_INVALID_CQ,
            rq: RIO_INVALID_RQ,
            buffer_id: RIO_INVALID_BUFFERID,
            slab,
            results: Vec::with_capacity(slots as usize),
            next_result: 0,
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
        // One extra entry for the send that the request queue must allow but we never post.
        inner.cq = unsafe { (inner.f().create_cq)(slots + 1, &notification) };
        if inner.cq == RIO_INVALID_CQ {
            return Err(wsa_error());
        }

        inner.rq = unsafe {
            (inner.f().create_rq)(
                socket.as_raw_socket() as _,
                slots,
                1,
                1,
                1,
                inner.cq,
                inner.cq,
                ptr::null(),
            )
        };
        if inner.rq == RIO_INVALID_RQ {
            return Err(wsa_error());
        }

        let slab_len = u32::try_from(inner.slab.layout.size())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        inner.buffer_id = unsafe { (inner.f().register_buffer)(inner.slab.ptr.cast(), slab_len) };
        if inner.buffer_id == RIO_INVALID_BUFFERID {
            return Err(wsa_error());
        }

        let signal = Arc::new(Signal {
            ready: AtomicBool::new(false),
            waker: Mutex::new(None),
        });
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
            for slot in 0..slots as usize {
                match inner.post(slot) {
                    Ok(()) => posted += 1,
                    Err(e) if posted == 0 => return Err(e),
                    Err(e) => {
                        debug!("posted only {posted} of {slots} RIO receives: {e}");
                        break;
                    }
                }
            }
            inner.commit()?;
        }

        Ok(this)
    }

    pub(super) fn recv(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        if inner.next_result == inner.results.len() {
            inner.dequeue()?;
        }

        let max = bufs.len().min(meta.len());
        let mut count = 0;
        while count < max {
            let Some(result) = inner.pop_result() else {
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

            if let Err(e) = inner.post(slot) {
                debug!("failed to re-post RIO receive: {e}");
            }
        }
        inner.commit()?;

        match count {
            0 => Err(io::ErrorKind::WouldBlock.into()),
            n => Ok(n),
        }
    }

    pub(super) fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.signal.ready.swap(false, Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }

        {
            let mut waker = self.signal.waker.lock().unwrap();
            match &*waker {
                Some(w) if w.will_wake(cx.waker()) => {}
                _ => *waker = Some(cx.waker().clone()),
            }
        }

        let mut inner = self.inner.lock().unwrap();
        if inner.next_result < inner.results.len() {
            return Poll::Ready(Ok(()));
        }

        let rc = unsafe { (inner.f().notify)(inner.cq) };
        if rc != 0 && rc != WinSock::WSAEALREADY {
            return Poll::Ready(Err(io::Error::from_raw_os_error(rc)));
        }

        // Completions that arrived before arming are not guaranteed to signal.
        if inner.dequeue()? > 0 || self.signal.ready.swap(false, Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }
}

impl Drop for RioRecv {
    fn drop(&mut self) {
        // Blocks until a running callback has returned.
        unsafe { UnregisterWaitEx(self.wait, INVALID_HANDLE_VALUE) };
        drop(unsafe { Arc::from_raw(self.wait_context) });
    }
}

impl std::fmt::Debug for RioRecv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RioRecv").finish_non_exhaustive()
    }
}

struct Signal {
    ready: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

unsafe extern "system" fn on_event(context: *mut c_void, _timed_out: bool) {
    let signal = unsafe { &*context.cast::<Signal>() };
    signal.ready.store(true, Ordering::Release);

    let waker = signal.waker.lock().unwrap().take();
    if let Some(waker) = waker {
        waker.wake();
    }
}

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
        *const WinSock::RIO_BUF,
        u32,
        *const WinSock::RIO_BUF,
        *const WinSock::RIO_BUF,
        *const WinSock::RIO_BUF,
        *const WinSock::RIO_BUF,
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
        dequeue: table.RIODequeueCompletion.ok_or_else(missing)?,
        notify: table.RIONotify.ok_or_else(missing)?,
    })
}

struct Inner {
    rio: Functions,
    event: HANDLE,
    cq: WinSock::RIO_CQ,
    rq: WinSock::RIO_RQ,
    buffer_id: WinSock::RIO_BUFFERID,
    slab: Slab,
    /// Dequeued completions, consumed from `next_result` on.
    results: Vec<WinSock::RIORESULT>,
    next_result: usize,
}

// SAFETY: the RIO handles and the slab are only accessed behind the `Mutex` in `RioRecv`.
unsafe impl Send for Inner {}

impl Inner {
    fn f(&self) -> &Functions {
        &self.rio
    }

    fn post(&mut self, slot: usize) -> io::Result<()> {
        let [data, addr, control] = self.slab.rio_bufs(self.buffer_id, slot);
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

    fn commit(&mut self) -> io::Result<()> {
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

    /// Refills `results` from the completion queue, if it is exhausted.
    fn dequeue(&mut self) -> io::Result<usize> {
        if self.next_result < self.results.len() {
            return Ok(self.results.len() - self.next_result);
        }

        self.results.clear();
        self.next_result = 0;

        let n = unsafe {
            (self.rio.dequeue)(
                self.cq,
                self.results.as_mut_ptr(),
                self.results.capacity() as u32,
            )
        };
        if n == WinSock::RIO_CORRUPT_CQ {
            return Err(io::Error::other("RIO completion queue is corrupt"));
        }
        // SAFETY: `RIODequeueCompletion` initialized `n <= capacity` entries.
        unsafe { self.results.set_len(n as usize) };

        Ok(n as usize)
    }

    fn pop_result(&mut self) -> Option<WinSock::RIORESULT> {
        let result = self.results.get(self.next_result).copied()?;
        self.next_result += 1;

        Some(result)
    }

    fn read(&self, slot: usize, len: usize, buf: &mut [u8]) -> io::Result<RecvMeta> {
        if len > buf.len() || len > self.slab.data_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("datagram of {len} bytes does not fit"),
            ));
        }

        let base = self.slab.slot_ptr(slot);
        // SAFETY: the slot's receive has completed, so the kernel no longer writes to it until it
        // is re-posted; `len` was checked against both buffers above.
        unsafe { ptr::copy_nonoverlapping(base, buf.as_mut_ptr(), len) };

        let addr = unsafe {
            ptr::read_unaligned(
                base.add(self.slab.addr_offset)
                    .cast::<WinSock::SOCKADDR_INET>(),
            )
        };
        let addr = sockaddr_inet_to_std(&addr)?;

        let control = unsafe { base.add(self.slab.control_offset) };
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
            if self.buffer_id != RIO_INVALID_BUFFERID {
                (self.rio.deregister_buffer)(self.buffer_id);
            }
            if !self.event.is_null() {
                CloseHandle(self.event);
            }
        }
    }
}

/// The registered memory: per slot, the datagram, its remote address and its control messages.
struct Slab {
    ptr: *mut u8,
    layout: Layout,
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

        let invalid = |_| io::Error::from(io::ErrorKind::InvalidInput);
        let size = slot_len
            .checked_mul(slots)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let layout = Layout::from_size_align(size, 4096).map_err(invalid)?;
        let ptr = unsafe { alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }

        Ok(Self {
            ptr,
            layout,
            slot_len,
            data_len: max_datagram_size,
            addr_offset,
            control_offset,
        })
    }

    fn slot_ptr(&self, slot: usize) -> *mut u8 {
        assert!(slot * self.slot_len < self.layout.size());
        unsafe { self.ptr.add(slot * self.slot_len) }
    }

    fn rio_bufs(&self, buffer_id: WinSock::RIO_BUFFERID, slot: usize) -> [WinSock::RIO_BUF; 3] {
        let offset = (slot * self.slot_len) as u32;
        let buf = |start: usize, len: usize| WinSock::RIO_BUF {
            BufferId: buffer_id,
            Offset: offset + start as u32,
            Length: len as u32,
        };

        [
            buf(0, self.data_len),
            buf(self.addr_offset, ADDR_LEN),
            buf(self.control_offset, CMSG_LEN),
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
