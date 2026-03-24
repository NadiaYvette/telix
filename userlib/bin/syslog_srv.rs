#![no_std]
#![no_main]

//! Syslog server — centralized logging service.
//!
//! Protocol tags (0x9000-0x9FFF):
//!   SYSLOG_OPEN(0x9000)  — open log, d0=facility, d1=ident_w0, d2=reply<<32
//!   SYSLOG_MSG(0x9010)   — log message, d0=priority, d1=msg_w0, d2=msg_w1, d3=len|reply<<32
//!   SYSLOG_CLOSE(0x9020) — close log, d0=handle, d2=reply<<32
//!   SYSLOG_READ(0x9030)  — read entry, d0=index, d2=reply<<32
//!   SYSLOG_OK(0x9100)    — success
//!   SYSLOG_ERROR(0x9F00) — error

extern crate userlib;

use userlib::syscall;

const SYSLOG_OPEN: u64 = 0x9000;
const SYSLOG_MSG: u64 = 0x9010;
const SYSLOG_CLOSE: u64 = 0x9020;
const SYSLOG_READ: u64 = 0x9030;

const SYSLOG_OK: u64 = 0x9100;
const SYSLOG_ERROR: u64 = 0x9F00;

// Syslog priority levels.
const LOG_EMERG: u32 = 0;
const LOG_ALERT: u32 = 1;
const LOG_CRIT: u32 = 2;
const LOG_WARNING: u32 = 4;

const RING_SIZE: usize = 64;
const MAX_HANDLES: usize = 8;

#[derive(Clone, Copy)]
struct LogEntry {
    timestamp_ns: u64,
    facility: u32,
    priority: u32,
    msg_w0: u64,
    msg_w1: u64,
}

impl LogEntry {
    const fn empty() -> Self {
        Self { timestamp_ns: 0, facility: 0, priority: 0, msg_w0: 0, msg_w1: 0 }
    }
}

#[derive(Clone, Copy)]
struct LogHandle {
    active: bool,
    facility: u32,
    ident_w0: u64,
}

impl LogHandle {
    const fn empty() -> Self {
        Self { active: false, facility: 0, ident_w0: 0 }
    }
}

static mut RING: [LogEntry; RING_SIZE] = [LogEntry::empty(); RING_SIZE];
static mut RING_HEAD: usize = 0;
static mut RING_COUNT: usize = 0;
static mut HANDLES: [LogHandle; MAX_HANDLES] = [LogHandle::empty(); MAX_HANDLES];

fn push_entry(entry: LogEntry) {
    unsafe {
        RING[RING_HEAD] = entry;
        RING_HEAD = (RING_HEAD + 1) % RING_SIZE;
        if RING_COUNT < RING_SIZE {
            RING_COUNT += 1;
        }
    }
}

fn get_entry(index: usize) -> Option<LogEntry> {
    unsafe {
        if index >= RING_COUNT {
            return None;
        }
        let actual = if RING_COUNT < RING_SIZE {
            index
        } else {
            (RING_HEAD + index) % RING_SIZE
        };
        Some(RING[actual])
    }
}

fn alloc_handle() -> Option<u32> {
    unsafe {
        for i in 0..MAX_HANDLES {
            if !HANDLES[i].active {
                HANDLES[i].active = true;
                return Some(i as u32);
            }
        }
    }
    None
}

/// Forward high-priority messages to debug console.
fn maybe_forward(priority: u32, msg_w0: u64, msg_w1: u64) {
    if priority <= LOG_WARNING {
        // Decode first 8 bytes of message for console output.
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(b"syslog: ");
        let bytes0 = msg_w0.to_le_bytes();
        let bytes1 = msg_w1.to_le_bytes();
        buf[8..16].copy_from_slice(&bytes0);
        buf[16..24].copy_from_slice(&bytes1);
        // Find actual length (trim trailing zeros).
        let mut len = 24;
        while len > 8 && buf[len - 1] == 0 {
            len -= 1;
        }
        syscall::debug_puts(&buf[..len]);
        syscall::debug_puts(b"\n");
    }
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) -> ! {
    let port = syscall::port_create() as u32;
    syscall::ns_register(b"syslog", port);

    loop {
        let msg = match syscall::recv_nb_msg(port) {
            Some(m) => m,
            None => {
                syscall::yield_now();
                continue;
            }
        };

        match msg.tag {
            SYSLOG_OPEN => {
                let facility = msg.data[0] as u32;
                let ident_w0 = msg.data[1];
                let reply = (msg.data[2] >> 32) as u32;

                match alloc_handle() {
                    Some(handle) => {
                        unsafe {
                            HANDLES[handle as usize].facility = facility;
                            HANDLES[handle as usize].ident_w0 = ident_w0;
                        }
                        syscall::send(reply, SYSLOG_OK, port as u64, handle as u64, 0, 0);
                    }
                    None => {
                        syscall::send(reply, SYSLOG_ERROR, 0, 0, 0, 0);
                    }
                }
            }

            SYSLOG_MSG => {
                let priority = msg.data[0] as u32;
                let msg_w0 = msg.data[1];
                let msg_w1 = msg.data[2];
                let reply = (msg.data[3] >> 32) as u32;

                let entry = LogEntry {
                    timestamp_ns: syscall::clock_gettime(),
                    facility: priority >> 3,
                    priority: priority & 0x7,
                    msg_w0,
                    msg_w1,
                };
                push_entry(entry);
                maybe_forward(priority & 0x7, msg_w0, msg_w1);

                syscall::send(reply, SYSLOG_OK, 0, 0, 0, 0);
            }

            SYSLOG_CLOSE => {
                let handle = msg.data[0] as u32;
                let reply = (msg.data[2] >> 32) as u32;

                if (handle as usize) < MAX_HANDLES {
                    unsafe { HANDLES[handle as usize].active = false; }
                }
                syscall::send(reply, SYSLOG_OK, 0, 0, 0, 0);
            }

            SYSLOG_READ => {
                let index = msg.data[0] as usize;
                let reply = (msg.data[2] >> 32) as u32;

                match get_entry(index) {
                    Some(entry) => {
                        // d0 = priority|facility<<16, d1 = msg_w0, d2 = msg_w1, d3 = timestamp
                        let info = (entry.priority as u64) | ((entry.facility as u64) << 16);
                        syscall::send(reply, SYSLOG_OK, info, entry.msg_w0, entry.msg_w1, entry.timestamp_ns);
                    }
                    None => {
                        syscall::send(reply, SYSLOG_ERROR, 0, 0, 0, 0);
                    }
                }
            }

            _ => {}
        }
    }
}
