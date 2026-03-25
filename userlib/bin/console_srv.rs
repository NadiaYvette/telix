#![no_std]
#![no_main]

//! Userspace console server.
//!
//! Owns serial I/O: polls UART for input via SYS_GETCHAR, writes output via debug_puts.
//! Provides CON_READ (line-buffered input) and CON_WRITE (output) to clients.

extern crate userlib;

use userlib::syscall;

// Console protocol constants.
const CON_READ: u64 = 0x3000;
const CON_READ_OK: u64 = 0x3001;
const CON_WRITE: u64 = 0x3100;
const CON_WRITE_OK: u64 = 0x3101;
const CON_POLL: u64 = 0x3110;
const CON_POLL_OK: u64 = 0x3111;

const MAX_LINE: usize = 64;

fn print_num(n: u64) {
    if n == 0 {
        syscall::debug_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut val = n;
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        syscall::debug_putchar(buf[i]);
    }
}

struct ConsoleSrv {
    line_buf: [u8; MAX_LINE],
    line_len: usize,
    line_ready: bool,
    /// Reply port of pending CON_READ client (at most one).
    pending_reader: u64,
}

impl ConsoleSrv {
    const fn new() -> Self {
        Self {
            line_buf: [0; MAX_LINE],
            line_len: 0,
            line_ready: false,
            pending_reader: u64::MAX,
        }
    }

    fn handle_char(&mut self, ch: u8) {
        match ch {
            // Enter (CR or LF).
            0x0D | 0x0A => {
                syscall::debug_putchar(b'\r');
                syscall::debug_putchar(b'\n');
                self.line_ready = true;
            }
            // Backspace or DEL.
            0x08 | 0x7F => {
                if self.line_len > 0 {
                    self.line_len -= 1;
                    // Erase character on terminal: \b, space, \b
                    syscall::debug_putchar(0x08);
                    syscall::debug_putchar(b' ');
                    syscall::debug_putchar(0x08);
                }
            }
            // Printable ASCII.
            0x20..=0x7E => {
                if self.line_len < MAX_LINE {
                    self.line_buf[self.line_len] = ch;
                    self.line_len += 1;
                    syscall::debug_putchar(ch);
                }
            }
            _ => {} // Ignore other characters.
        }
    }

    fn send_line(&mut self, reply_port: u64) {
        let len = self.line_len.min(24); // Max inline = 3 words = 24 bytes
        let mut words = [0u64; 3];
        for i in 0..len {
            words[i / 8] |= (self.line_buf[i] as u64) << ((i % 8) * 8);
        }
        syscall::send(reply_port, CON_READ_OK,
            self.line_len as u64, words[0], words[1], words[2]);
        // Reset line buffer.
        self.line_len = 0;
        self.line_ready = false;
    }

    fn handle_write(&self, msg: &syscall::Message) {
        let len = (msg.data[2] & 0xFFFF_FFFF) as usize;
        let reply_port = msg.data[2] >> 32;

        // Unpack inline bytes from data[0], data[1], data[3] (up to 24 bytes).
        let words = [msg.data[0], msg.data[1], msg.data[3]];
        let actual = len.min(24);
        for i in 0..actual {
            let word_idx = if i < 16 { i / 8 } else { 2 };
            let byte_off = if i < 16 { i % 8 } else { (i - 16) % 8 };
            let ch = (words[word_idx] >> (byte_off * 8)) as u8;
            syscall::debug_putchar(ch);
        }

        if reply_port != u64::MAX && reply_port != 0 {
            syscall::send_nb(reply_port, CON_WRITE_OK, actual as u64, 0);
        }
    }

    fn handle_read(&mut self, msg: &syscall::Message) {
        let reply_port = msg.data[0] >> 32;

        if self.line_ready {
            self.send_line(reply_port);
        } else {
            self.pending_reader = reply_port;
        }
    }
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [console_srv] starting\n");

    let port = syscall::port_create();
    syscall::ns_register(b"console", port);

    syscall::debug_puts(b"  [console_srv] ready on port ");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    let mut srv = ConsoleSrv::new();

    loop {
        // 1. Poll UART for input.
        while let Some(ch) = syscall::getchar() {
            srv.handle_char(ch);
        }

        // 2. If line ready and there's a pending reader, deliver it.
        if srv.line_ready && srv.pending_reader != u64::MAX {
            let rp = srv.pending_reader;
            srv.pending_reader = u64::MAX;
            srv.send_line(rp);
        }

        // 3. Check for client messages (non-blocking).
        if let Some(msg) = syscall::recv_nb_msg(port) {
            match msg.tag {
                CON_WRITE => srv.handle_write(&msg),
                CON_READ => srv.handle_read(&msg),
                CON_POLL => {
                    let events = (msg.data[2] & 0xFFFF) as u16;
                    let rp = msg.data[2] >> 32;
                    // Console is always writable. Not readable (yet).
                    let mut revents = 0u16;
                    if events & 0x0004 != 0 {
                        revents |= 0x0004; // POLLOUT
                    }
                    syscall::send(rp, CON_POLL_OK, revents as u64, 0, 0, 0);
                }
                _ => {}
            }
        }

        syscall::yield_now();
    }
}
