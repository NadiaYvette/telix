#![no_std]
#![no_main]

//! Pipe server — manages anonymous pipes with 4KB ring buffers.
//!
//! Each pipe is a (read_end, write_end) pair sharing a ring buffer.
//! Handles: read_handle = slot*2, write_handle = slot*2+1.
//!
//! Protocol tags (0x5000-0x5FFF):
//!   PIPE_CREATE(0x5010) — create pipe pair, reply d0=read_h, d1=write_h
//!   PIPE_WRITE(0x5020)  — write data, d0=handle, d1=w0, d3=w1, d2=len|reply
//!   PIPE_READ(0x5030)   — read data, d0=handle, d2=reply<<32
//!   PIPE_CLOSE(0x5040)  — close handle, d0=handle, d2=reply<<32

extern crate userlib;

use userlib::syscall;

// Protocol tags.
const PIPE_CREATE: u64 = 0x5010;
const PIPE_WRITE: u64 = 0x5020;
const PIPE_WRITE_ASYNC: u64 = 0x5022;
const PIPE_WRITE_REPLY: u64 = 0x5023;
const PIPE_READ: u64 = 0x5030;
const PIPE_READ_ASYNC: u64 = 0x5032;
const PIPE_READ_REPLY: u64 = 0x5033;
const PIPE_CLOSE: u64 = 0x5040;
const PIPE_POLL: u64 = 0x5050;
const PIPE_SET_REPLY_PORT: u64 = 0x5060;
const PIPE_SET_REPLY_PORT_OK: u64 = 0x5061;

const POLL_SUBSCRIBE: u64 = 0xF010;
const POLL_UNSUBSCRIBE: u64 = 0xF020;
const POLL_NOTIFY: u64 = 0xF030;

const PIPE_OK: u64 = 0x5100;
const PIPE_EOF: u64 = 0x51FF;
const PIPE_ERROR: u64 = 0x5F00;

/// Reply port registered by linux_srv via PIPE_SET_REPLY_PORT.  When
/// non-zero, PIPE_WRITE_REPLY / PIPE_READ_REPLY notifications are
/// sent here via send_nb_4 instead of the normal sync reply path.
/// Mirrors the FS_READ_ASYNC pattern landed for the 14 FS servers.
static ASYNC_REPLY_PORT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

// Limits.
const MAX_PIPES: usize = 32;
const BUF_SIZE: usize = 4096;

struct PipeSlot {
    active: bool,
    buf: [u8; BUF_SIZE],
    head: usize,
    tail: usize,
    writer_closed: bool,
    reader_closed: bool,
    // Deferred reply-cap handle for a blocked reader (u64::MAX = none).
    // Saved via sys_reply_take; fulfilled later via sys_reply_to.
    recv_reply_cap: u64,
    // Async-pending reader (Phase A1 of linux_srv worker-pool work).
    // When a PIPE_READ_ASYNC arrives and the pipe is empty + writer
    // not closed, park the request in these fields instead of via
    // sys_reply_take.  Fulfilled by send_nb_4 to ASYNC_REPLY_PORT
    // when data arrives or writer closes.  Only one async reader
    // per slot for now (matches existing single recv_reply_cap).
    async_read_pending: bool,
    async_read_correlation: u64,
    async_read_max_len: u32,
    // Poll subscription ports (u64::MAX = no subscriber).
    // When readiness changes, we send POLL_NOTIFY to these ports.
    poll_notify_read: u64,  // subscriber watching the read end
    poll_notify_write: u64, // subscriber watching the write end
}

impl PipeSlot {
    const fn empty() -> Self {
        Self {
            active: false,
            buf: [0; BUF_SIZE],
            head: 0,
            tail: 0,
            writer_closed: false,
            reader_closed: false,
            recv_reply_cap: u64::MAX,
            async_read_pending: false,
            async_read_correlation: 0,
            async_read_max_len: 0,
            poll_notify_read: u64::MAX,
            poll_notify_write: u64::MAX,
        }
    }

    fn len(&self) -> usize {
        if self.head >= self.tail {
            self.head - self.tail
        } else {
            BUF_SIZE - self.tail + self.head
        }
    }

    fn free(&self) -> usize {
        BUF_SIZE - 1 - self.len()
    }

    fn push(&mut self, data: &[u8]) -> usize {
        let mut written = 0;
        for &b in data {
            if self.free() == 0 {
                break;
            }
            self.buf[self.head] = b;
            self.head = (self.head + 1) % BUF_SIZE;
            written += 1;
        }
        written
    }

    fn pop(&mut self, out: &mut [u8]) -> usize {
        let mut read = 0;
        while read < out.len() && self.len() > 0 {
            out[read] = self.buf[self.tail];
            self.tail = (self.tail + 1) % BUF_SIZE;
            read += 1;
        }
        read
    }
}

static mut PIPES: [PipeSlot; MAX_PIPES] = [const { PipeSlot::empty() }; MAX_PIPES];

fn alloc_pipe() -> Option<u32> {
    unsafe {
        for i in 0..MAX_PIPES {
            if !PIPES[i].active {
                PIPES[i] = PipeSlot::empty();
                PIPES[i].active = true;
                return Some(i as u32);
            }
        }
    }
    None
}

/// Pack up to 16 bytes into two u64 words.
fn pack_bytes(data: &[u8], len: usize) -> (u64, u64) {
    let mut w0 = 0u64;
    let mut w1 = 0u64;
    let n = if len < 16 { len } else { 16 };
    for i in 0..n {
        if i < 8 {
            w0 |= (data[i] as u64) << (i * 8);
        } else {
            w1 |= (data[i] as u64) << ((i - 8) * 8);
        }
    }
    (w0, w1)
}

/// Deliver data (or EOF) to a pipe that has a blocked reader whose
/// reply-cap was saved via sys_reply_take.  Sync path.
fn try_wake_reader(slot: u32) {
    let s = unsafe { &mut PIPES[slot as usize] };
    if s.recv_reply_cap == u64::MAX {
        return;
    }
    let cap = s.recv_reply_cap;
    if s.len() > 0 {
        let mut tmp = [0u8; 16];
        let n = s.pop(&mut tmp);
        let (w0, w1) = pack_bytes(&tmp, n);
        s.recv_reply_cap = u64::MAX;
        let _ = syscall::reply_to(cap, PIPE_OK, w0, w1, n as u64, 0);
    } else if s.writer_closed {
        s.recv_reply_cap = u64::MAX;
        let _ = syscall::reply_to(cap, PIPE_EOF, 0, 0, 0, 0);
    }
}

/// Async equivalent of try_wake_reader: satisfy a PIPE_READ_ASYNC
/// that was parked because the pipe was empty.  Sends PIPE_READ_REPLY
/// via send_nb_4 to the registered ASYNC_REPLY_PORT.
fn try_wake_async_reader(slot: u32) {
    let s = unsafe { &mut PIPES[slot as usize] };
    if !s.async_read_pending {
        return;
    }
    let reply_port = ASYNC_REPLY_PORT.load(core::sync::atomic::Ordering::Acquire);
    if reply_port == 0 {
        // No reply port registered — drop silently; will retry on next wake.
        return;
    }
    let correlation = s.async_read_correlation;
    let max_len = s.async_read_max_len as usize;
    if s.len() > 0 {
        let mut tmp = [0u8; 16];
        let n = s.pop(&mut tmp).min(max_len);
        let (w0, w1) = pack_bytes(&tmp, n);
        s.async_read_pending = false;
        s.async_read_correlation = 0;
        s.async_read_max_len = 0;
        let _ = syscall::send_nb_4(reply_port, PIPE_READ_REPLY, correlation, w0, w1, n as u64);
    } else if s.writer_closed {
        s.async_read_pending = false;
        s.async_read_correlation = 0;
        s.async_read_max_len = 0;
        // n=0 means EOF or error; linux_srv's continuation treats 0
        // as "no more data — read(2) returns 0".
        let _ = syscall::send_nb_4(reply_port, PIPE_READ_REPLY, correlation, 0, 0, 0);
    }
}

/// Send POLL_NOTIFY to the read-end subscriber (data available or HUP).
fn notify_poll_read(slot: u32) {
    let s = unsafe { &PIPES[slot as usize] };
    if s.poll_notify_read == u64::MAX {
        return;
    }
    let mut revents: u16 = 0;
    if s.len() > 0 {
        revents |= 0x0001; // POLLIN
    }
    if s.writer_closed && s.len() == 0 {
        revents |= 0x0010; // POLLHUP
    }
    if revents != 0 {
        syscall::send_nb(s.poll_notify_read, POLL_NOTIFY, revents as u64, 0);
    }
}

/// Send POLL_NOTIFY to the write-end subscriber (space available or ERR).
fn notify_poll_write(slot: u32) {
    let s = unsafe { &PIPES[slot as usize] };
    if s.poll_notify_write == u64::MAX {
        return;
    }
    let mut revents: u16 = 0;
    if s.reader_closed {
        revents |= 0x0008; // POLLERR
    } else if s.free() > 0 {
        revents |= 0x0004; // POLLOUT
    }
    if revents != 0 {
        syscall::send_nb(s.poll_notify_write, POLL_NOTIFY, revents as u64, 0);
    }
}

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    let svc_port = if arg0 != 0 && arg0 != u64::MAX {
        arg0 // Pre-created port from parent (smoke test path).
    } else {
        syscall::port_create()
    };
    syscall::ns_register(b"pipe", svc_port);

    // Call/reply server: recv_with_cap installs a reply-cap on this
    // thread; every request path must consume it exactly once — either
    // via sys_reply (immediate) or sys_reply_take + sys_reply_to
    // (deferred, for blocking PIPE_READ).
    loop {
        let msg = match syscall::recv_with_cap(svc_port) {
            Some(m) => m,
            None => continue,
        };

        let tag = msg.tag;

        match tag {
            PIPE_CREATE => {
                if let Some(slot) = alloc_pipe() {
                    let read_h = slot * 2;
                    let write_h = slot * 2 + 1;
                    let _ = syscall::reply(PIPE_OK, read_h as u64, write_h as u64, 0, 0, 0);
                } else {
                    let _ = syscall::reply(PIPE_ERROR, 0, 0, 0, 0, 0);
                }
            }

            PIPE_WRITE => {
                let handle = msg.data[0] as u32;
                let len = (msg.data[2] & 0xFFFF) as usize;
                let len = if len > 16 { 16 } else { len };

                if handle & 1 == 0 || (handle / 2) as usize >= MAX_PIPES {
                    let _ = syscall::reply(PIPE_ERROR, 0, 0, 0, 0, 0);
                    continue;
                }
                let slot = (handle / 2) as usize;
                let s = unsafe { &mut PIPES[slot] };
                if !s.active || s.reader_closed {
                    let _ = syscall::reply(PIPE_ERROR, 0, 0, 0, 0, 0);
                    continue;
                }

                let was_empty = s.len() == 0;

                let mut tmp = [0u8; 16];
                let b0 = msg.data[1].to_le_bytes();
                let b1 = msg.data[3].to_le_bytes();
                let mut i = 0;
                while i < len && i < 8 {
                    tmp[i] = b0[i];
                    i += 1;
                }
                while i < len && i < 16 {
                    tmp[i] = b1[i - 8];
                    i += 1;
                }

                let written = s.push(&tmp[..len]);
                let _ = syscall::reply(PIPE_OK, written as u64, 0, 0, 0, 0);

                // Wake blocked reader if any.
                try_wake_reader(slot as u32);

                // Notify poll subscriber on read end (empty → non-empty).
                if was_empty && written > 0 {
                    notify_poll_read(slot as u32);
                }
            }

            PIPE_READ => {
                let handle = msg.data[0] as u32;

                if handle & 1 != 0 || (handle / 2) as usize >= MAX_PIPES {
                    let _ = syscall::reply(PIPE_ERROR, 0, 0, 0, 0, 0);
                    continue;
                }
                let slot = (handle / 2) as usize;
                let s = unsafe { &mut PIPES[slot] };
                if !s.active {
                    let _ = syscall::reply(PIPE_ERROR, 0, 0, 0, 0, 0);
                    continue;
                }

                let was_full = s.free() == 0;

                if s.len() > 0 {
                    let mut tmp = [0u8; 16];
                    let n = s.pop(&mut tmp);
                    let (w0, w1) = pack_bytes(&tmp, n);
                    let _ = syscall::reply(PIPE_OK, w0, w1, n as u64, 0, 0);

                    // Notify poll subscriber on write end (full → has space).
                    if was_full {
                        notify_poll_write(slot as u32);
                    }
                } else if s.writer_closed {
                    let _ = syscall::reply(PIPE_EOF, 0, 0, 0, 0, 0);
                } else {
                    // Defer the reply: take the cap handle and stash it.
                    // Fulfilled later in try_wake_reader when a writer
                    // pushes data or closes.
                    let cap = syscall::reply_take();
                    if cap == u64::MAX {
                        // No cap held — shouldn't happen but be safe.
                        continue;
                    }
                    s.recv_reply_cap = cap;
                }
            }

            PIPE_CLOSE => {
                let handle = msg.data[0] as u32;
                let is_write = handle & 1 != 0;
                let slot_idx = (handle / 2) as usize;

                if slot_idx >= MAX_PIPES {
                    let _ = syscall::reply(PIPE_ERROR, 0, 0, 0, 0, 0);
                    continue;
                }
                let s = unsafe { &mut PIPES[slot_idx] };
                if !s.active {
                    let _ = syscall::reply(PIPE_ERROR, 0, 0, 0, 0, 0);
                    continue;
                }

                if is_write {
                    s.writer_closed = true;
                    let _ = syscall::reply(PIPE_OK, 0, 0, 0, 0, 0);
                    // After replying, wake blocked reader so it sees EOF.
                    try_wake_reader(slot_idx as u32);
                    // Notify read-end poll subscriber (POLLHUP).
                    notify_poll_read(slot_idx as u32);
                } else {
                    s.reader_closed = true;
                    let _ = syscall::reply(PIPE_OK, 0, 0, 0, 0, 0);
                    // Notify write-end poll subscriber (POLLERR — broken pipe).
                    notify_poll_write(slot_idx as u32);
                }

                // Re-read after potential reader-wake.
                let s2 = unsafe { &mut PIPES[slot_idx] };
                if s2.writer_closed && s2.reader_closed {
                    s2.active = false;
                }
            }

            PIPE_POLL => {
                syscall::debug_puts(b"  [pipe] POLL recv\n");
                let handle = msg.data[0] as u32;
                let events = (msg.data[2] & 0xFFFF) as u16;
                let is_write = handle & 1 != 0;
                let slot_idx = (handle / 2) as usize;

                if slot_idx >= MAX_PIPES {
                    let _ = syscall::reply(PIPE_ERROR, 0, 0, 0, 0, 0);
                    continue;
                }
                let s = unsafe { &PIPES[slot_idx] };
                if !s.active {
                    let _ = syscall::reply(PIPE_ERROR, 0, 0, 0, 0, 0);
                    continue;
                }

                let mut revents = 0u16;
                if is_write {
                    if s.reader_closed {
                        revents |= 0x0008; // POLLERR
                    } else if s.free() > 0 && (events & 0x0004 != 0) {
                        revents |= 0x0004; // POLLOUT
                    }
                } else {
                    if s.len() > 0 && (events & 0x0001 != 0) {
                        revents |= 0x0001; // POLLIN
                    }
                    if s.writer_closed && s.len() == 0 {
                        revents |= 0x0010; // POLLHUP
                    }
                }
                let rc = syscall::reply(PIPE_OK, revents as u64, 0, 0, 0, 0);
                syscall::debug_puts(b"  [pipe] POLL reply rc=");
                if rc == 0 { syscall::debug_puts(b"0\n"); } else { syscall::debug_puts(b"ERR\n"); }
            }

            PIPE_SET_REPLY_PORT => {
                // The client (linux_srv) sends this via send_nb_4 — no
                // reply cap is installed.  ACK by sending
                // PIPE_SET_REPLY_PORT_OK to the very port being
                // registered (it's also the client's BACKEND_REPLY_PORT,
                // which is parked in its main port_set wait).  This
                // avoids the 30 s CALL_REPLY_TIMEOUT trap a sync
                // syscall::call would hit when the host has the client's
                // vCPU paused at registration time.
                let reply_port = msg.data[0];
                ASYNC_REPLY_PORT.store(reply_port, core::sync::atomic::Ordering::Release);
                let _ = syscall::send_nb_4(
                    reply_port, PIPE_SET_REPLY_PORT_OK, 0, 0, 0, 0,
                );
            }

            PIPE_WRITE_ASYNC => {
                // Wire format mirrors PIPE_WRITE but with correlation
                // displacing the len field's word:
                //   d0 = handle (low 32) | len (high 32)
                //   d1 = bytes 0-7
                //   d2 = correlation
                //   d3 = bytes 8-15
                let handle = (msg.data[0] & 0xFFFF_FFFF) as u32;
                let len = ((msg.data[0] >> 32) & 0xFFFF_FFFF) as usize;
                let len = if len > 16 { 16 } else { len };
                let correlation = msg.data[2];
                let reply_port = ASYNC_REPLY_PORT.load(core::sync::atomic::Ordering::Acquire);
                if reply_port == 0 {
                    // No reply port registered — drop silently.
                    continue;
                }
                if handle & 1 == 0 || (handle / 2) as usize >= MAX_PIPES {
                    let _ = syscall::send_nb_4(reply_port, PIPE_WRITE_REPLY, correlation, 0, 0, 0);
                    continue;
                }
                let slot = (handle / 2) as usize;
                let s = unsafe { &mut PIPES[slot] };
                if !s.active || s.reader_closed {
                    let _ = syscall::send_nb_4(reply_port, PIPE_WRITE_REPLY, correlation, 0, 0, 0);
                    continue;
                }

                let was_empty = s.len() == 0;

                let mut tmp = [0u8; 16];
                let b0 = msg.data[1].to_le_bytes();
                let b1 = msg.data[3].to_le_bytes();
                let mut i = 0;
                while i < len && i < 8 {
                    tmp[i] = b0[i];
                    i += 1;
                }
                while i < len && i < 16 {
                    tmp[i] = b1[i - 8];
                    i += 1;
                }

                let written = s.push(&tmp[..len]);
                let _ = syscall::send_nb_4(
                    reply_port, PIPE_WRITE_REPLY, correlation, written as u64, 0, 0,
                );

                // Wake any blocked reader (sync or async) — data arrived.
                try_wake_reader(slot as u32);
                try_wake_async_reader(slot as u32);

                if was_empty && written > 0 {
                    notify_poll_read(slot as u32);
                }
            }

            PIPE_READ_ASYNC => {
                // Wire format:
                //   d0 = handle (low 32) | max_len (high 32)
                //   d1 = correlation
                //   d2-3 = unused
                let handle = (msg.data[0] & 0xFFFF_FFFF) as u32;
                let max_len = ((msg.data[0] >> 32) & 0xFFFF_FFFF) as u32;
                let correlation = msg.data[1];
                let reply_port = ASYNC_REPLY_PORT.load(core::sync::atomic::Ordering::Acquire);
                if reply_port == 0 {
                    continue;
                }
                if handle & 1 != 0 || (handle / 2) as usize >= MAX_PIPES {
                    let _ = syscall::send_nb_4(reply_port, PIPE_READ_REPLY, correlation, 0, 0, 0);
                    continue;
                }
                let slot = (handle / 2) as usize;
                let s = unsafe { &mut PIPES[slot] };
                if !s.active {
                    let _ = syscall::send_nb_4(reply_port, PIPE_READ_REPLY, correlation, 0, 0, 0);
                    continue;
                }

                let was_full = s.free() == 0;
                let max_n = (max_len as usize).min(16);

                if s.len() > 0 {
                    let mut tmp = [0u8; 16];
                    let n = {
                        // pop up to max_n bytes
                        let mut taken = [0u8; 16];
                        let got = s.pop(&mut taken);
                        let take = got.min(max_n);
                        tmp[..take].copy_from_slice(&taken[..take]);
                        // any bytes popped beyond max_n are lost; with
                        // max_n=16 (the inline limit) this can't happen.
                        take
                    };
                    let (w0, w1) = pack_bytes(&tmp, n);
                    let _ = syscall::send_nb_4(reply_port, PIPE_READ_REPLY, correlation, w0, w1, n as u64);
                    if was_full {
                        notify_poll_write(slot as u32);
                    }
                } else if s.writer_closed {
                    // EOF: n=0 in the reply.
                    let _ = syscall::send_nb_4(reply_port, PIPE_READ_REPLY, correlation, 0, 0, 0);
                } else {
                    // Park the async read; fulfilled later by
                    // try_wake_async_reader.  Only one async reader per
                    // slot — overwrite is safe in practice because
                    // linux_srv serialises per-pipe reads, but be
                    // defensive: if there's an existing pending reader,
                    // satisfy this one immediately with 0 bytes.
                    if s.async_read_pending {
                        let _ = syscall::send_nb_4(reply_port, PIPE_READ_REPLY, correlation, 0, 0, 0);
                    } else {
                        s.async_read_pending = true;
                        s.async_read_correlation = correlation;
                        s.async_read_max_len = max_len;
                    }
                }
            }

            POLL_SUBSCRIBE => {
                // data[0] = pipe handle, data[1] = notify_port, data[2] = events
                let handle = msg.data[0] as u32;
                let notify_port = msg.data[1];
                let is_write = handle & 1 != 0;
                let slot_idx = (handle / 2) as usize;

                if slot_idx >= MAX_PIPES {
                    let _ = syscall::reply(PIPE_ERROR, 0, 0, 0, 0, 0);
                    continue;
                }
                let s = unsafe { &mut PIPES[slot_idx] };
                if !s.active {
                    let _ = syscall::reply(PIPE_ERROR, 0, 0, 0, 0, 0);
                    continue;
                }

                if is_write {
                    s.poll_notify_write = notify_port;
                } else {
                    s.poll_notify_read = notify_port;
                }

                // Consume reply cap (harmless no-op for fire-and-forget sends).
                let _ = syscall::reply(PIPE_OK, 0, 0, 0, 0, 0);

                // If already ready, send immediate notification.
                if is_write {
                    notify_poll_write(slot_idx as u32);
                } else {
                    notify_poll_read(slot_idx as u32);
                }
            }

            POLL_UNSUBSCRIBE => {
                // data[0] = pipe handle, data[1] = notify_port
                let handle = msg.data[0] as u32;
                let is_write = handle & 1 != 0;
                let slot_idx = (handle / 2) as usize;

                if slot_idx < MAX_PIPES {
                    let s = unsafe { &mut PIPES[slot_idx] };
                    if is_write {
                        s.poll_notify_write = u64::MAX;
                    } else {
                        s.poll_notify_read = u64::MAX;
                    }
                }
                let _ = syscall::reply(PIPE_OK, 0, 0, 0, 0, 0);
            }

            _ => {
                let _ = syscall::reply(PIPE_ERROR, 0, 0, 0, 0, 0);
            }
        }
    }
}
