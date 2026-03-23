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
const PIPE_READ: u64 = 0x5030;
const PIPE_CLOSE: u64 = 0x5040;

const PIPE_OK: u64 = 0x5100;
const PIPE_EOF: u64 = 0x51FF;
const PIPE_ERROR: u64 = 0x5F00;

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
    recv_reply: u32, // blocked reader's reply port (0xFFFFFFFF = none)
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
            recv_reply: 0xFFFFFFFF,
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

fn reply(port: u32, tag: u64, d0: u64, d1: u64, d2: u64, d3: u64) {
    syscall::send(port, tag, d0, d1, d2, d3);
}

/// Deliver data (or EOF) to a pipe that has a blocked reader.
fn try_wake_reader(slot: u32) {
    let s = unsafe { &mut PIPES[slot as usize] };
    if s.recv_reply == 0xFFFFFFFF {
        return;
    }
    let rp = s.recv_reply;
    if s.len() > 0 {
        let mut tmp = [0u8; 16];
        let n = s.pop(&mut tmp);
        let (w0, w1) = pack_bytes(&tmp, n);
        s.recv_reply = 0xFFFFFFFF;
        reply(rp, PIPE_OK, w0, w1, n as u64, 0);
    } else if s.writer_closed {
        s.recv_reply = 0xFFFFFFFF;
        reply(rp, PIPE_EOF, 0, 0, 0, 0);
    }
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    let svc_port = syscall::port_create() as u32;
    syscall::ns_register(b"pipe", svc_port);

    loop {
        let msg = match syscall::recv_msg(svc_port) {
            Some(m) => m,
            None => continue,
        };

        let tag = msg.tag;
        let reply_port = (msg.data[2] >> 32) as u32;

        match tag {
            PIPE_CREATE => {
                if let Some(slot) = alloc_pipe() {
                    let read_h = slot * 2;
                    let write_h = slot * 2 + 1;
                    reply(reply_port, PIPE_OK, read_h as u64, write_h as u64, 0, 0);
                } else {
                    reply(reply_port, PIPE_ERROR, 0, 0, 0, 0);
                }
            }

            PIPE_WRITE => {
                let handle = msg.data[0] as u32;
                let len = (msg.data[2] & 0xFFFF) as usize;
                let len = if len > 16 { 16 } else { len };

                // Must be a write handle (odd).
                if handle & 1 == 0 || (handle / 2) as usize >= MAX_PIPES {
                    if reply_port != 0xFFFFFFFF {
                        reply(reply_port, PIPE_ERROR, 0, 0, 0, 0);
                    }
                    continue;
                }
                let slot = (handle / 2) as usize;
                let s = unsafe { &mut PIPES[slot] };
                if !s.active || s.reader_closed {
                    if reply_port != 0xFFFFFFFF {
                        reply(reply_port, PIPE_ERROR, 0, 0, 0, 0);
                    }
                    continue;
                }

                // Unpack data bytes.
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
                if reply_port != 0xFFFFFFFF {
                    reply(reply_port, PIPE_OK, written as u64, 0, 0, 0);
                }

                // Wake blocked reader if any.
                try_wake_reader(slot as u32);
            }

            PIPE_READ => {
                let handle = msg.data[0] as u32;

                // Must be a read handle (even).
                if handle & 1 != 0 || (handle / 2) as usize >= MAX_PIPES {
                    reply(reply_port, PIPE_ERROR, 0, 0, 0, 0);
                    continue;
                }
                let slot = (handle / 2) as usize;
                let s = unsafe { &mut PIPES[slot] };
                if !s.active {
                    reply(reply_port, PIPE_ERROR, 0, 0, 0, 0);
                    continue;
                }

                if s.len() > 0 {
                    let mut tmp = [0u8; 16];
                    let n = s.pop(&mut tmp);
                    let (w0, w1) = pack_bytes(&tmp, n);
                    reply(reply_port, PIPE_OK, w0, w1, n as u64, 0);
                } else if s.writer_closed {
                    reply(reply_port, PIPE_EOF, 0, 0, 0, 0);
                } else {
                    // Block — store reply port.
                    s.recv_reply = reply_port;
                }
            }

            PIPE_CLOSE => {
                let handle = msg.data[0] as u32;
                let is_write = handle & 1 != 0;
                let slot_idx = (handle / 2) as usize;

                if slot_idx >= MAX_PIPES {
                    reply(reply_port, PIPE_ERROR, 0, 0, 0, 0);
                    continue;
                }
                let s = unsafe { &mut PIPES[slot_idx] };
                if !s.active {
                    reply(reply_port, PIPE_ERROR, 0, 0, 0, 0);
                    continue;
                }

                if is_write {
                    s.writer_closed = true;
                    // Wake blocked reader so it sees EOF.
                    try_wake_reader(slot_idx as u32);
                } else {
                    s.reader_closed = true;
                }

                // Free slot if both ends closed.
                if s.writer_closed && s.reader_closed {
                    s.active = false;
                }

                reply(reply_port, PIPE_OK, 0, 0, 0, 0);
            }

            _ => {
                if reply_port != 0 && reply_port != 0xFFFFFFFF {
                    reply(reply_port, PIPE_ERROR, 0, 0, 0, 0);
                }
            }
        }
    }
}
