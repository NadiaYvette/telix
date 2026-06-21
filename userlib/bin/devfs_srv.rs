#![no_std]
#![no_main]

//! devfs — device filesystem server.
//!
//! Serves static device entries: null, zero, full, random, urandom,
//! console, tty. Implements the standard FS protocol.

extern crate userlib;

use userlib::completion::{Reply, Request, Rings};
use userlib::syscall;
use core::sync::atomic::{AtomicU64, Ordering};

static ASYNC_READ_REPLY_PORT: AtomicU64 = AtomicU64::new(0);

// FS protocol constants.
const FS_OPEN: u64 = 0x2000;
const FS_OPEN_OK: u64 = 0x2001;
const FS_READ: u64 = 0x2100;
const FS_READ_ASYNC: u64 = 0x2102;
const FS_READ_REPLY: u64 = 0x2103;
const FS_SET_READ_REPLY_PORT: u64 = 0x2104;
const FS_SET_READ_REPLY_PORT_OK: u64 = 0x2105;
const FS_READ_OK: u64 = 0x2101;
const FS_READDIR: u64 = 0x2200;
const FS_READDIR_OK: u64 = 0x2201;
const FS_READDIR_END: u64 = 0x2202;
const FS_STAT: u64 = 0x2300;
const FS_STAT_OK: u64 = 0x2301;
const FS_CLOSE: u64 = 0x2400;
const FS_CLOSE_OK: u64 = 0x2401;
const FS_WRITE: u64 = 0x2600;
const FS_WRITE_OK: u64 = 0x2601;
const FS_ERROR: u64 = 0x2F00;

// Console protocol.
const CON_READ: u64 = 0x3000;
const CON_READ_OK: u64 = 0x3001;
const CON_WRITE: u64 = 0x3100;
const CON_WRITE_OK: u64 = 0x3101;

const ERR_NOT_FOUND: u64 = 1;
const ERR_INVALID: u64 = 3;
const ERR_NOSPC: u64 = 5;

const MAX_OPEN: usize = 16;
const MAX_INLINE: usize = 24;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DeviceType {
    Null,
    Zero,
    Full,
    Random,
    Urandom,
    Console,
    Tty,
}

const NUM_DEVICES: usize = 7;

struct DeviceEntry {
    name: &'static [u8],
    dev_type: DeviceType,
}

static DEVICES: [DeviceEntry; NUM_DEVICES] = [
    DeviceEntry {
        name: b"null",
        dev_type: DeviceType::Null,
    },
    DeviceEntry {
        name: b"zero",
        dev_type: DeviceType::Zero,
    },
    DeviceEntry {
        name: b"full",
        dev_type: DeviceType::Full,
    },
    DeviceEntry {
        name: b"random",
        dev_type: DeviceType::Random,
    },
    DeviceEntry {
        name: b"urandom",
        dev_type: DeviceType::Urandom,
    },
    DeviceEntry {
        name: b"console",
        dev_type: DeviceType::Console,
    },
    DeviceEntry {
        name: b"tty",
        dev_type: DeviceType::Tty,
    },
];

#[derive(Clone, Copy)]
struct OpenHandle {
    dev_idx: usize,
    active: bool,
}

impl OpenHandle {
    const fn empty() -> Self {
        Self {
            dev_idx: 0,
            active: false,
        }
    }
}

/// Simple LCG PRNG state.
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0xDEAD_BEEF_CAFE_1234
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 33) as u8
    }
}

fn unpack_name(d0: u64, d1: u64, len: usize) -> ([u8; 16], usize) {
    let mut buf = [0u8; 16];
    let actual = len.min(16);
    for i in 0..actual {
        if i < 8 {
            buf[i] = (d0 >> (i * 8)) as u8;
        } else {
            buf[i] = (d1 >> ((i - 8) * 8)) as u8;
        }
    }
    (buf, actual)
}

fn find_device(name: &[u8], name_len: usize) -> Option<usize> {
    for (i, dev) in DEVICES.iter().enumerate() {
        if dev.name.len() == name_len {
            let mut eq = true;
            for j in 0..name_len {
                if dev.name[j] != name[j] {
                    eq = false;
                    break;
                }
            }
            if eq {
                return Some(i);
            }
        }
    }
    None
}

fn pack_inline_data(data: &[u8]) -> [u64; 3] {
    let mut words = [0u64; 3];
    for (i, &b) in data.iter().enumerate().take(MAX_INLINE) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [devfs_srv] starting\n");

    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();
    syscall::ns_register(b"devfs", port);
    syscall::ns_register(b"devfs_task", syscall::aspace_id());

    // Look up console_srv for tty/console proxying.
    let console_port = {
        let mut found = 0u64;
        for _ in 0..50 {
            if let Some(p) = syscall::ns_lookup(b"console") {
                found = p;
                break;
            }
            syscall::yield_now();
        }
        found
    };

    // Create a reply port for console IPC.
    let con_reply = syscall::port_create();

    // Seed RNG from clock.
    let mut rng = Rng::new(syscall::clock_gettime());

    syscall::debug_puts(b"  [devfs_srv] ready\n");

    let mut handles = [OpenHandle::empty(); MAX_OPEN];

    // Completion-ABI server (Phase 1): switch to the SQ/CQ rings so inbound
    // calls land in our CQ and we answer via OP_REPLY through the shared
    // `serve` helper — the completion equivalent of the legacy
    // recv_with_cap/reply loop. FS_READ_ASYNC keeps its fire-and-forget send
    // to the client's read-reply port and returns None (no reply-cap answer).
    let rings = match Rings::setup(8) {
        Some(r) => r,
        None => {
            syscall::debug_puts(b"  [devfs_srv] io_setup FAIL\n");
            syscall::exit(1);
        }
    };

    rings.serve(|req: Request| -> Option<Reply> {
        match req.tag {
            FS_OPEN => {
                let name_len = (req.data[2] & 0xFFFF_FFFF) as usize;
                let (name, nlen) = unpack_name(req.data[0], req.data[1], name_len);

                match find_device(&name, nlen) {
                    Some(di) => {
                        let mut h = u64::MAX;
                        for (i, hnd) in handles.iter_mut().enumerate() {
                            if !hnd.active {
                                hnd.active = true;
                                hnd.dev_idx = di;
                                h = i as u64;
                                break;
                            }
                        }
                        if h == u64::MAX {
                            Some(Reply { tag: FS_ERROR, data: [ERR_INVALID, 0, 0, 0, 0] })
                        } else {
                            Some(Reply { tag: FS_OPEN_OK, data: [h, 0, my_aspace as u64, 0, 0] })
                        }
                    }
                    None => Some(Reply { tag: FS_ERROR, data: [ERR_NOT_FOUND, 0, 0, 0, 0] }),
                }
            }

            FS_SET_READ_REPLY_PORT => {
                ASYNC_READ_REPLY_PORT.store(req.data[0], Ordering::Release);
                Some(Reply { tag: FS_SET_READ_REPLY_PORT_OK, data: [0, 0, 0, 0, 0] })
            }

            FS_READ_ASYNC => {
                let handle = (req.data[0] & 0xFFFF_FFFF) as usize;
                let length = ((req.data[0] >> 32) & 0xFFFF_FFFF) as usize;
                let _offset = req.data[1];
                let grant_va = req.data[2] as usize;
                let correlation = req.data[3];
                let reply_port = ASYNC_READ_REPLY_PORT.load(Ordering::Acquire);
                if reply_port == 0 { return None; }
                let send = |bytes: u64| {
                    let _ = syscall::send_nb_4(reply_port, FS_READ_REPLY, correlation, bytes, 0, 0);
                };
                if handle >= MAX_OPEN || !handles[handle].active || grant_va == 0 {
                    send(0); return None;
                }
                let dev_type = DEVICES[handles[handle].dev_idx].dev_type;
                let bytes = match dev_type {
                    DeviceType::Null => 0u64,
                    DeviceType::Zero | DeviceType::Full => {
                        let n = length.min(4096);
                        unsafe { core::ptr::write_bytes(grant_va as *mut u8, 0, n); }
                        n as u64
                    }
                    DeviceType::Random | DeviceType::Urandom => {
                        let n = length.min(4096);
                        let p = grant_va as *mut u8;
                        for i in 0..n { unsafe { *p.add(i) = rng.next_u8(); } }
                        n as u64
                    }
                    // Console / Tty involve a sub-call to console_srv;
                    // not supported on the async fast path yet — caller
                    // falls back to sync FS_READ for these.
                    DeviceType::Console | DeviceType::Tty => 0u64,
                };
                send(bytes);
                None
            }

            FS_READ => {
                let handle = req.data[0] as usize;
                let _offset = req.data[1];
                let length = (req.data[2] & 0xFFFF_FFFF) as usize;
                let grant_va = req.data[3] as usize;

                if handle >= MAX_OPEN || !handles[handle].active {
                    return Some(Reply { tag: FS_ERROR, data: [ERR_INVALID, 0, 0, 0, 0] });
                }

                let dev_type = DEVICES[handles[handle].dev_idx].dev_type;

                match dev_type {
                    DeviceType::Null => {
                        // EOF — 0 bytes.
                        Some(Reply { tag: FS_READ_OK, data: [0, 0, 0, 0, 0] })
                    }
                    DeviceType::Zero | DeviceType::Full => {
                        let to_read = length.min(MAX_INLINE);
                        if grant_va != 0 {
                            unsafe {
                                core::ptr::write_bytes(grant_va as *mut u8, 0, length.min(4096));
                            }
                            Some(Reply { tag: FS_READ_OK, data: [length.min(4096) as u64, 0, 0, 0, 0] })
                        } else {
                            // Inline zeros.
                            Some(Reply { tag: FS_READ_OK, data: [to_read as u64, 0, 0, 0, 0] })
                        }
                    }
                    DeviceType::Random | DeviceType::Urandom => {
                        let to_read = length.min(MAX_INLINE);
                        if grant_va != 0 {
                            let actual = length.min(4096);
                            let p = grant_va as *mut u8;
                            for i in 0..actual {
                                unsafe {
                                    *p.add(i) = rng.next_u8();
                                }
                            }
                            Some(Reply { tag: FS_READ_OK, data: [actual as u64, 0, 0, 0, 0] })
                        } else {
                            let mut buf = [0u8; MAX_INLINE];
                            for i in 0..to_read {
                                buf[i] = rng.next_u8();
                            }
                            let packed = pack_inline_data(&buf[..to_read]);
                            Some(Reply {
                                tag: FS_READ_OK,
                                data: [to_read as u64, packed[0], packed[1], packed[2], 0],
                            })
                        }
                    }
                    DeviceType::Console | DeviceType::Tty => {
                        if console_port == 0 {
                            return Some(Reply { tag: FS_READ_OK, data: [0, 0, 0, 0, 0] });
                        }
                        // Send CON_READ to console_srv (legacy protocol path).
                        let d0 = (con_reply as u64) << 32;
                        syscall::send(console_port, CON_READ, d0, 0, 0, 0);
                        if let Some(cr) = syscall::recv_msg(con_reply) {
                            if cr.tag == CON_READ_OK {
                                let len = cr.data[0] as usize;
                                let actual = len.min(length);
                                Some(Reply {
                                    tag: FS_READ_OK,
                                    data: [actual as u64, cr.data[1], cr.data[2], cr.data[3], 0],
                                })
                            } else {
                                Some(Reply { tag: FS_READ_OK, data: [0, 0, 0, 0, 0] })
                            }
                        } else {
                            Some(Reply { tag: FS_READ_OK, data: [0, 0, 0, 0, 0] })
                        }
                    }
                }
            }

            FS_WRITE => {
                let handle = req.data[0] as usize;
                let length = (req.data[1] & 0xFFFF_FFFF) as usize;
                let grant_va = req.data[2] as usize;

                if handle >= MAX_OPEN || !handles[handle].active {
                    return Some(Reply { tag: FS_ERROR, data: [ERR_INVALID, 0, 0, 0, 0] });
                }

                let dev_type = DEVICES[handles[handle].dev_idx].dev_type;

                match dev_type {
                    DeviceType::Full => {
                        // ENOSPC.
                        Some(Reply { tag: FS_ERROR, data: [ERR_NOSPC, 0, 0, 0, 0] })
                    }
                    DeviceType::Null
                    | DeviceType::Zero
                    | DeviceType::Random
                    | DeviceType::Urandom => {
                        // Discard.
                        Some(Reply { tag: FS_WRITE_OK, data: [length as u64, 0, 0, 0, 0] })
                    }
                    DeviceType::Console | DeviceType::Tty => {
                        if console_port == 0 {
                            return Some(Reply { tag: FS_WRITE_OK, data: [0, 0, 0, 0, 0] });
                        }
                        // Pack data for CON_WRITE: legacy path to console_srv.
                        let actual = length.min(24);
                        let mut d0 = 0u64;
                        let mut d1 = 0u64;
                        let mut d3 = 0u64;

                        if grant_va != 0 {
                            let p = grant_va as *const u8;
                            for i in 0..actual {
                                let b = unsafe { *p.add(i) } as u64;
                                if i < 8 {
                                    d0 |= b << (i * 8);
                                } else if i < 16 {
                                    d1 |= b << ((i - 8) * 8);
                                } else {
                                    d3 |= b << ((i - 16) * 8);
                                }
                            }
                        }
                        let d2 = (actual as u64) | ((con_reply as u64) << 32);
                        syscall::send(console_port, CON_WRITE, d0, d1, d2, d3);
                        // Wait for ack.
                        syscall::recv_msg(con_reply);
                        Some(Reply { tag: FS_WRITE_OK, data: [actual as u64, 0, 0, 0, 0] })
                    }
                }
            }

            FS_STAT => {
                let handle = req.data[0] as usize;

                if handle >= MAX_OPEN || !handles[handle].active {
                    return Some(Reply { tag: FS_ERROR, data: [ERR_INVALID, 0, 0, 0, 0] });
                }

                let di = handles[handle].dev_idx;
                // mode = 0o020666 (char device, rw for all)
                Some(Reply { tag: FS_STAT_OK, data: [0, 0o020666u64, 0, di as u64, 0] })
            }

            FS_READDIR => {
                let start_offset = req.data[0] as usize;

                if start_offset < NUM_DEVICES {
                    let dev = &DEVICES[start_offset];
                    let nlen = dev.name.len();
                    let mut name_lo = 0u64;
                    let mut name_hi = 0u64;
                    for j in 0..nlen.min(8) {
                        name_lo |= (dev.name[j] as u64) << (j * 8);
                    }
                    for j in 8..nlen.min(16) {
                        name_hi |= (dev.name[j] as u64) << ((j - 8) * 8);
                    }
                    Some(Reply {
                        tag: FS_READDIR_OK,
                        data: [0, name_lo, name_hi, (start_offset + 1) as u64, 0],
                    })
                } else {
                    Some(Reply { tag: FS_READDIR_END, data: [0, 0, 0, 0, 0] })
                }
            }

            FS_CLOSE => {
                let handle = req.data[0] as usize;
                if handle < MAX_OPEN && handles[handle].active {
                    handles[handle].active = false;
                }
                Some(Reply { tag: FS_CLOSE_OK, data: [0, 0, 0, 0, 0] })
            }

            _ => Some(Reply { tag: FS_ERROR, data: [ERR_INVALID, 0, 0, 0, 0] }),
        }
    });
}
