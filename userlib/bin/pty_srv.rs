#![no_std]
#![no_main]

//! PTY server — manages pseudo-terminal pairs with line discipline.
//!
//! Each PTY is a (master, slave) pair sharing two ring buffers:
//! - m2s: master writes → line discipline → slave reads
//! - s2m: slave writes → output processing → master reads
//!
//! Handle encoding: master_handle = slot*2, slave_handle = slot*2+1.
//!
//! Protocol tags (0x9000-0x9FFF):
//!   PTY_OPEN(0x9000)  — allocate PTY pair
//!   PTY_WRITE(0x9010) — write data
//!   PTY_READ(0x9020)  — read data (blocks if empty)
//!   PTY_CLOSE(0x9030) — close handle
//!   PTY_IOCTL(0x9040) — terminal ioctls
//!   PTY_POLL(0x9050)  — poll readiness

extern crate userlib;

use userlib::syscall;

// Protocol tags.
const PTY_OPEN: u64 = 0x9000;
const PTY_OPEN_OK: u64 = 0x9001;
const PTY_WRITE: u64 = 0x9010;
const PTY_WRITE_OK: u64 = 0x9011;
const PTY_READ: u64 = 0x9020;
const PTY_READ_OK: u64 = 0x9021;
const PTY_CLOSE: u64 = 0x9030;
const PTY_CLOSE_OK: u64 = 0x9031;
const PTY_IOCTL: u64 = 0x9040;
const PTY_IOCTL_OK: u64 = 0x9041;
const PTY_POLL: u64 = 0x9050;
const PTY_POLL_OK: u64 = 0x9051;
const PTY_EOF: u64 = 0x90FF;
const PTY_ERROR: u64 = 0x9F00;

// Ioctl requests.
const TCGETS: u32 = 0x5401;
const TCSETS: u32 = 0x5402;
const TIOCGWINSZ: u32 = 0x5413;
const TIOCSWINSZ: u32 = 0x5414;
const TIOCGPGRP: u32 = 0x540F;
const TIOCSPGRP: u32 = 0x5410;

// Termios lflag bits.
const ISIG: u32 = 0x0001;
const ICANON: u32 = 0x0002;
const ECHO: u32 = 0x0008;

// Termios oflag bits.
const OPOST: u32 = 0x0001;
const ONLCR: u32 = 0x0004;

// Limits.
const MAX_PTYS: usize = 8;
const BUF_SIZE: usize = 256;
const CANON_SIZE: usize = 256;
const NO_READER: u64 = u64::MAX;

// Control character indices.
const VINTR: usize = 0; // ^C
const VEOF: usize = 1; // ^D
const VERASE: usize = 2; // Backspace
const VKILL: usize = 3; // ^U
const VSUSP: usize = 4; // ^Z

struct RingBuf {
    buf: [u8; BUF_SIZE],
    head: usize,
    tail: usize,
}

impl RingBuf {
    const fn new() -> Self {
        Self {
            buf: [0; BUF_SIZE],
            head: 0,
            tail: 0,
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

    fn push_byte(&mut self, b: u8) -> bool {
        if self.free() == 0 {
            return false;
        }
        self.buf[self.head] = b;
        self.head = (self.head + 1) % BUF_SIZE;
        true
    }

    fn pop(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0;
        while n < out.len() && self.len() > 0 {
            out[n] = self.buf[self.tail];
            self.tail = (self.tail + 1) % BUF_SIZE;
            n += 1;
        }
        n
    }
}

struct PtyPair {
    active: bool,
    // Master→slave (through line discipline).
    m2s: RingBuf,
    // Slave→master (through output processing).
    s2m: RingBuf,
    // Line discipline state.
    lflag: u32,
    oflag: u32,
    cc: [u8; 8], // control chars
    canon_buf: [u8; CANON_SIZE],
    canon_len: usize,
    canon_ready: bool,
    // Window size.
    ws_row: u16,
    ws_col: u16,
    // Foreground process group.
    fg_pgrp: u64,
    // Blocked readers (deferred reply).
    master_reader: u64,
    slave_reader: u64,
    // Close tracking.
    master_closed: bool,
    slave_closed: bool,
    // EOF pending for slave.
    slave_eof: bool,
}

impl PtyPair {
    const fn new() -> Self {
        Self {
            active: false,
            m2s: RingBuf::new(),
            s2m: RingBuf::new(),
            lflag: ECHO | ICANON | ISIG,
            oflag: OPOST | ONLCR,
            cc: [
                3,    // VINTR: ^C
                4,    // VEOF: ^D
                0x7F, // VERASE: DEL
                0x15, // VKILL: ^U
                0x1A, // VSUSP: ^Z
                0, 0, 0,
            ],
            canon_buf: [0; CANON_SIZE],
            canon_len: 0,
            canon_ready: false,
            ws_row: 24,
            ws_col: 80,
            fg_pgrp: 0,
            master_reader: NO_READER,
            slave_reader: NO_READER,
            master_closed: false,
            slave_closed: false,
            slave_eof: false,
        }
    }
}

static mut PTYS: [PtyPair; MAX_PTYS] = [const { PtyPair::new() }; MAX_PTYS];

fn pack_bytes(data: &[u8], len: usize) -> (u64, u64) {
    let mut w0 = 0u64;
    let mut w1 = 0u64;
    let n = if len > 16 { 16 } else { len };
    for i in 0..n {
        if i < 8 {
            w0 |= (data[i] as u64) << (i * 8);
        } else {
            w1 |= (data[i] as u64) << ((i - 8) * 8);
        }
    }
    (w0, w1)
}

fn reply(port: u64, tag: u64, d0: u64, d1: u64, d2: u64, d3: u64) {
    syscall::send(port, tag, d0, d1, d2, d3);
}

/// Try to deliver data to a blocked master reader.
fn try_wake_master(slot: usize) {
    let p = unsafe { &mut PTYS[slot] };
    if p.master_reader == NO_READER {
        return;
    }
    if p.s2m.len() > 0 {
        let rp = p.master_reader;
        let mut tmp = [0u8; 16];
        let n = p.s2m.pop(&mut tmp);
        let (w0, w1) = pack_bytes(&tmp, n);
        p.master_reader = NO_READER;
        reply(rp, PTY_READ_OK, w0, w1, n as u64, 0);
    } else if p.slave_closed {
        let rp = p.master_reader;
        p.master_reader = NO_READER;
        reply(rp, PTY_EOF, 0, 0, 0, 0);
    }
}

/// Try to deliver data to a blocked slave reader.
fn try_wake_slave(slot: usize) {
    let p = unsafe { &mut PTYS[slot] };
    if p.slave_reader == NO_READER {
        return;
    }
    if p.m2s.len() > 0 {
        let rp = p.slave_reader;
        let mut tmp = [0u8; 16];
        let n = p.m2s.pop(&mut tmp);
        let (w0, w1) = pack_bytes(&tmp, n);
        p.slave_reader = NO_READER;
        reply(rp, PTY_READ_OK, w0, w1, n as u64, 0);
    } else if p.slave_eof {
        let rp = p.slave_reader;
        p.slave_reader = NO_READER;
        p.slave_eof = false;
        reply(rp, PTY_EOF, 0, 0, 0, 0);
    } else if p.master_closed {
        let rp = p.slave_reader;
        p.slave_reader = NO_READER;
        reply(rp, PTY_EOF, 0, 0, 0, 0);
    }
}

/// Process a byte written to the master (input to the slave through line discipline).
fn ldisc_input(slot: usize, b: u8) {
    let p = unsafe { &mut PTYS[slot] };

    // Signal generation.
    if p.lflag & ISIG != 0 {
        if b == p.cc[VINTR] {
            if p.fg_pgrp != 0 {
                syscall::kill_pgroup(p.fg_pgrp, 2); // SIGINT
            }
            // Echo ^C.
            if p.lflag & ECHO != 0 {
                p.s2m.push_byte(b'^');
                p.s2m.push_byte(b'C');
                p.s2m.push_byte(b'\n');
            }
            return;
        }
        if b == p.cc[VSUSP] {
            if p.fg_pgrp != 0 {
                syscall::kill_pgroup(p.fg_pgrp, 20); // SIGTSTP
            }
            if p.lflag & ECHO != 0 {
                p.s2m.push_byte(b'^');
                p.s2m.push_byte(b'Z');
                p.s2m.push_byte(b'\n');
            }
            return;
        }
    }

    if p.lflag & ICANON != 0 {
        // Canonical mode.
        if b == p.cc[VERASE] {
            // Backspace.
            if p.canon_len > 0 {
                p.canon_len -= 1;
                if p.lflag & ECHO != 0 {
                    p.s2m.push_byte(8); // BS
                    p.s2m.push_byte(b' ');
                    p.s2m.push_byte(8); // BS
                }
            }
        } else if b == p.cc[VKILL] {
            // Kill line.
            if p.lflag & ECHO != 0 {
                for _ in 0..p.canon_len {
                    p.s2m.push_byte(8);
                    p.s2m.push_byte(b' ');
                    p.s2m.push_byte(8);
                }
            }
            p.canon_len = 0;
        } else if b == p.cc[VEOF] {
            // ^D: flush line or signal EOF.
            if p.canon_len > 0 {
                // Flush current buffer to m2s.
                for i in 0..p.canon_len {
                    p.m2s.push_byte(p.canon_buf[i]);
                }
                p.canon_len = 0;
                p.canon_ready = true;
            } else {
                // EOF at start of line.
                p.slave_eof = true;
            }
        } else if b == b'\r' || b == b'\n' {
            // Line complete.
            if p.canon_len < CANON_SIZE {
                p.canon_buf[p.canon_len] = b'\n';
                p.canon_len += 1;
            }
            // Echo the newline.
            if p.lflag & ECHO != 0 {
                p.s2m.push_byte(b'\r');
                p.s2m.push_byte(b'\n');
            }
            // Move canon_buf to m2s.
            for i in 0..p.canon_len {
                p.m2s.push_byte(p.canon_buf[i]);
            }
            p.canon_len = 0;
            p.canon_ready = true;
        } else {
            // Regular character.
            if p.canon_len < CANON_SIZE {
                p.canon_buf[p.canon_len] = b;
                p.canon_len += 1;
                if p.lflag & ECHO != 0 {
                    p.s2m.push_byte(b);
                }
            }
        }
    } else {
        // Raw mode: pass through directly.
        p.m2s.push_byte(b);
        if p.lflag & ECHO != 0 {
            p.s2m.push_byte(b);
        }
    }
}

/// Process a byte written by the slave (output processing for master).
fn opost_output(slot: usize, b: u8) {
    let p = unsafe { &mut PTYS[slot] };
    if p.oflag & OPOST != 0 && p.oflag & ONLCR != 0 && b == b'\n' {
        p.s2m.push_byte(b'\r');
    }
    p.s2m.push_byte(b);
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    let svc_port = syscall::port_create();
    syscall::ns_register(b"pty", svc_port);

    loop {
        let msg = match syscall::recv_msg(svc_port) {
            Some(m) => m,
            None => continue,
        };

        let tag = msg.tag;
        let reply_port = msg.data[2] >> 32;

        match tag {
            PTY_OPEN => {
                // Allocate a PTY pair.
                let mut slot = usize::MAX;
                unsafe {
                    for i in 0..MAX_PTYS {
                        if !PTYS[i].active {
                            PTYS[i] = PtyPair::new();
                            PTYS[i].active = true;
                            slot = i;
                            break;
                        }
                    }
                }
                if slot == usize::MAX {
                    reply(reply_port, PTY_ERROR, 0, 0, 0, 0);
                } else {
                    let master_h = (slot * 2) as u32;
                    let slave_h = (slot * 2 + 1) as u32;
                    let d0 = (master_h as u64) | ((slave_h as u64) << 32);
                    reply(reply_port, PTY_OPEN_OK, d0, slot as u64, 0, 0);
                }
            }

            PTY_WRITE => {
                let handle = (msg.data[0] & 0xFFFF_FFFF) as u32;
                let len = (msg.data[2] & 0xFFFF) as usize;
                let len = if len > 16 { 16 } else { len };

                let is_slave = handle & 1 != 0;
                let slot = (handle / 2) as usize;

                if slot >= MAX_PTYS {
                    if reply_port != NO_READER {
                        reply(reply_port, PTY_ERROR, 0, 0, 0, 0);
                    }
                    continue;
                }
                let active = unsafe { PTYS[slot].active };
                if !active {
                    if reply_port != NO_READER {
                        reply(reply_port, PTY_ERROR, 0, 0, 0, 0);
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

                if is_slave {
                    // Slave writing → output processing → s2m buffer.
                    for j in 0..len {
                        opost_output(slot, tmp[j]);
                    }
                    try_wake_master(slot);
                } else {
                    // Master writing → line discipline → m2s buffer.
                    for j in 0..len {
                        ldisc_input(slot, tmp[j]);
                    }
                    // Wake blocked slave reader if data available.
                    try_wake_slave(slot);
                    // Wake blocked master reader if echo data.
                    try_wake_master(slot);
                }

                if reply_port != NO_READER {
                    reply(reply_port, PTY_WRITE_OK, len as u64, 0, 0, 0);
                }
            }

            PTY_READ => {
                let handle = (msg.data[0] & 0xFFFF_FFFF) as u32;
                let is_slave = handle & 1 != 0;
                let slot = (handle / 2) as usize;

                if slot >= MAX_PTYS {
                    reply(reply_port, PTY_ERROR, 0, 0, 0, 0);
                    continue;
                }

                let p = unsafe { &mut PTYS[slot] };
                if !p.active {
                    reply(reply_port, PTY_ERROR, 0, 0, 0, 0);
                    continue;
                }

                if is_slave {
                    // Slave reads from m2s.
                    if p.m2s.len() > 0 {
                        let mut tmp = [0u8; 16];
                        let n = p.m2s.pop(&mut tmp);
                        let (w0, w1) = pack_bytes(&tmp, n);
                        reply(reply_port, PTY_READ_OK, w0, w1, n as u64, 0);
                    } else if p.slave_eof {
                        p.slave_eof = false;
                        reply(reply_port, PTY_EOF, 0, 0, 0, 0);
                    } else if p.master_closed {
                        reply(reply_port, PTY_EOF, 0, 0, 0, 0);
                    } else {
                        // Block.
                        p.slave_reader = reply_port;
                    }
                } else {
                    // Master reads from s2m.
                    if p.s2m.len() > 0 {
                        let mut tmp = [0u8; 16];
                        let n = p.s2m.pop(&mut tmp);
                        let (w0, w1) = pack_bytes(&tmp, n);
                        reply(reply_port, PTY_READ_OK, w0, w1, n as u64, 0);
                    } else if p.slave_closed {
                        reply(reply_port, PTY_EOF, 0, 0, 0, 0);
                    } else {
                        // Block.
                        p.master_reader = reply_port;
                    }
                }
            }

            PTY_CLOSE => {
                let handle = (msg.data[0] & 0xFFFF_FFFF) as u32;
                let is_slave = handle & 1 != 0;
                let slot = (handle / 2) as usize;

                if slot >= MAX_PTYS {
                    reply(reply_port, PTY_ERROR, 0, 0, 0, 0);
                    continue;
                }

                let p = unsafe { &mut PTYS[slot] };
                if !p.active {
                    reply(reply_port, PTY_ERROR, 0, 0, 0, 0);
                    continue;
                }

                if is_slave {
                    p.slave_closed = true;
                    try_wake_master(slot);
                } else {
                    p.master_closed = true;
                    try_wake_slave(slot);
                }

                if p.master_closed && p.slave_closed {
                    p.active = false;
                }

                reply(reply_port, PTY_CLOSE_OK, 0, 0, 0, 0);
            }

            PTY_IOCTL => {
                let handle = (msg.data[0] & 0xFFFF_FFFF) as u32;
                let request = (msg.data[0] >> 32) as u32;
                let slot = (handle / 2) as usize;

                if slot >= MAX_PTYS {
                    reply(reply_port, PTY_ERROR, 0, 0, 0, 0);
                    continue;
                }
                let p = unsafe { &mut PTYS[slot] };
                if !p.active {
                    reply(reply_port, PTY_ERROR, 0, 0, 0, 0);
                    continue;
                }

                match request {
                    TIOCGWINSZ => {
                        let d0 = (p.ws_row as u64) | ((p.ws_col as u64) << 16);
                        reply(reply_port, PTY_IOCTL_OK, d0, 0, 0, 0);
                    }
                    TIOCSWINSZ => {
                        p.ws_row = (msg.data[1] & 0xFFFF) as u16;
                        p.ws_col = ((msg.data[1] >> 16) & 0xFFFF) as u16;
                        reply(reply_port, PTY_IOCTL_OK, 0, 0, 0, 0);
                    }
                    TCGETS => {
                        // Pack lflag and oflag into d0, cc into d1.
                        let d0 = (p.lflag as u64) | ((p.oflag as u64) << 32);
                        let mut d1 = 0u64;
                        for i in 0..8 {
                            d1 |= (p.cc[i] as u64) << (i * 8);
                        }
                        reply(reply_port, PTY_IOCTL_OK, d0, d1, 0, 0);
                    }
                    TCSETS => {
                        // Unpack lflag, oflag from arg0, cc from arg1.
                        p.lflag = (msg.data[1] & 0xFFFF_FFFF) as u32;
                        p.oflag = (msg.data[1] >> 32) as u32;
                        let cc_val = msg.data[3];
                        for i in 0..8 {
                            p.cc[i] = ((cc_val >> (i * 8)) & 0xFF) as u8;
                        }
                        reply(reply_port, PTY_IOCTL_OK, 0, 0, 0, 0);
                    }
                    TIOCGPGRP => {
                        reply(reply_port, PTY_IOCTL_OK, p.fg_pgrp as u64, 0, 0, 0);
                    }
                    TIOCSPGRP => {
                        p.fg_pgrp = msg.data[1];
                        reply(reply_port, PTY_IOCTL_OK, 0, 0, 0, 0);
                    }
                    _ => {
                        reply(reply_port, PTY_ERROR, 0, 0, 0, 0);
                    }
                }
            }

            PTY_POLL => {
                let handle = (msg.data[0] & 0xFFFF_FFFF) as u32;
                let events = (msg.data[2] & 0xFFFF) as u16;
                let is_slave = handle & 1 != 0;
                let slot = (handle / 2) as usize;

                if slot >= MAX_PTYS {
                    reply(reply_port, PTY_ERROR, 0, 0, 0, 0);
                    continue;
                }
                let p = unsafe { &PTYS[slot] };
                if !p.active {
                    reply(reply_port, PTY_ERROR, 0, 0, 0, 0);
                    continue;
                }

                let mut revents = 0u16;
                if is_slave {
                    if (p.m2s.len() > 0 || p.slave_eof) && (events & 0x0001 != 0) {
                        revents |= 0x0001; // POLLIN
                    }
                    if p.master_closed && p.m2s.len() == 0 {
                        revents |= 0x0010; // POLLHUP
                    }
                    if events & 0x0004 != 0 {
                        revents |= 0x0004; // POLLOUT (always writable)
                    }
                } else {
                    if p.s2m.len() > 0 && (events & 0x0001 != 0) {
                        revents |= 0x0001; // POLLIN
                    }
                    if p.slave_closed && p.s2m.len() == 0 {
                        revents |= 0x0010; // POLLHUP
                    }
                    if events & 0x0004 != 0 {
                        revents |= 0x0004; // POLLOUT
                    }
                }
                reply(reply_port, PTY_POLL_OK, revents as u64, 0, 0, 0);
            }

            _ => {
                if reply_port != 0 && reply_port != NO_READER {
                    reply(reply_port, PTY_ERROR, 0, 0, 0, 0);
                }
            }
        }
    }
}
