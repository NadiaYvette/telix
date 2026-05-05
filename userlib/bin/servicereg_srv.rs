//! servicereg_srv — content-addressed service registry (Piece (b)).
//!
//! The kernel's name server (`svc_register` / `svc_lookup`) is
//! string-keyed: callers ask for `b"linux"` and get back a port.  That's
//! topology-addressed in the same sense IP routing is — the binding is
//! between an opaque name and a specific port on a specific device.
//!
//! `servicereg_srv` is the content-addressed layer that sits above it.
//! Callers register (and look up) by **service UUID + method**, plus an
//! optional constraint set in the future.  Same device today; cross-
//! device tomorrow when discovery_srv + proxy_srv land — at which point
//! lookup walks local first, then queries known peers' servicereg
//! instances over the secure channel, and returns whichever endpoint
//! best matches the constraint set.
//!
//! Wire conventions (chosen so cross-device extension is mechanical):
//!   - **Service UUID**: 16 bytes.  Conventionally version-4 random,
//!     but bytes are opaque to the registry.  Authors of services pick
//!     and publish a UUID per service kind (e.g., one for "camera
//!     capture stream," one for "filesystem read"), the same UUID
//!     across all implementations / devices.
//!   - **Method**: u32.  Per-service-UUID enum of operations.  Bit
//!     positions in a u64 method-mask record which methods a registrant
//!     supports (so a partial implementation registers only what it
//!     actually serves).
//!   - **Capability hint** (returned by lookup, opaque u64 for now):
//!     reserved for cross-device attenuated capability bundles in
//!     piece (c) of the design.  Today it returns 0.
//!
//! Service name (in the kernel name server): registered as `b"servicereg"`.
//! Callers reach this server via `syscall::ns_lookup(b"servicereg")` —
//! the userlib `services::*` helpers wrap that.

#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

// ---------------------------------------------------------------------------
// Wire protocol.  Tags in the 0x7E range to avoid collision with other
// servers (nat=0x7C, zfs=0x7D, free).
// ---------------------------------------------------------------------------

/// Register a service.  Caller's intent: "I provide service-UUID `u`
/// and support methods specified by mask `m`; route lookups to my port."
/// data[0..2] = uuid bytes 0..16, packed (low-byte-first) into two u64
///   words: data[0] = bytes 0..8, data[1] = bytes 8..16.
/// data[2] = method-mask (u64, bit i = method i supported).
/// data[3] = service port (where lookups should resolve to).
pub const SVCREG_REGISTER: u64 = 0x7E01;
pub const SVCREG_REGISTER_OK: u64 = 0x7E02;
pub const SVCREG_REGISTER_FAIL: u64 = 0x7E0F;

/// Unregister.  Caller passes the same UUID; the entry is removed if the
/// caller is the owner.  data[0..2] = uuid bytes; data[2] = caller port
/// (must match the registered port).
pub const SVCREG_UNREGISTER: u64 = 0x7E03;
pub const SVCREG_UNREGISTER_OK: u64 = 0x7E04;

/// Look up a service endpoint.
/// data[0..2] = uuid bytes; data[2] = method index (low 32 bits).
/// Reply data[0] = port, data[1] = capability-hint (placeholder 0 for
/// piece (b); piece (c) will carry the attenuated capability bundle).
pub const SVCREG_LOOKUP: u64 = 0x7E10;
pub const SVCREG_LOOKUP_OK: u64 = 0x7E11;
pub const SVCREG_LOOKUP_NOTFOUND: u64 = 0x7E1F;

/// Stats / introspection: number of registered services.
pub const SVCREG_STATS: u64 = 0x7E20;
pub const SVCREG_STATS_OK: u64 = 0x7E21;

/// Maximum simultaneous registrations.
const MAX_ENTRIES: usize = 64;

#[derive(Copy, Clone)]
struct Entry {
    in_use: bool,
    uuid: [u8; 16],
    method_mask: u64,
    port: u64,
}

impl Entry {
    const fn empty() -> Self {
        Self {
            in_use: false,
            uuid: [0; 16],
            method_mask: 0,
            port: 0,
        }
    }
}

static mut TABLE: [Entry; MAX_ENTRIES] = [Entry::empty(); MAX_ENTRIES];

fn uuid_from_words(w0: u64, w1: u64) -> [u8; 16] {
    let mut u = [0u8; 16];
    u[0..8].copy_from_slice(&w0.to_le_bytes());
    u[8..16].copy_from_slice(&w1.to_le_bytes());
    u
}

fn find_by_uuid(uuid: &[u8; 16]) -> Option<usize> {
    unsafe {
        for i in 0..MAX_ENTRIES {
            if TABLE[i].in_use && &TABLE[i].uuid == uuid {
                return Some(i);
            }
        }
    }
    None
}

#[unsafe(no_mangle)]
fn main(_a0: u64, _a1: u64, _a2: u64) {
    syscall::debug_puts(b"[servicereg_srv] starting\n");

    let port = syscall::port_create();
    if port == u64::MAX {
        syscall::debug_puts(b"[servicereg_srv] port_create FAIL\n");
        syscall::exit(1);
    }
    if !syscall::ns_register(b"servicereg", port) {
        syscall::debug_puts(b"[servicereg_srv] ns_register FAIL\n");
        syscall::exit(1);
    }
    syscall::debug_puts(b"[servicereg_srv] ready on port ");
    print_num(port);
    syscall::debug_puts(b"\n");

    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => continue,
        };
        match msg.tag {
            SVCREG_REGISTER => {
                let uuid = uuid_from_words(msg.data[0], msg.data[1]);
                let method_mask = msg.data[2];
                let svc_port = msg.data[3];
                // Reuse the slot if this UUID is already registered
                // (re-registration updates the port + mask).
                let slot = match find_by_uuid(&uuid) {
                    Some(i) => Some(i),
                    None => {
                        let mut found = None;
                        unsafe {
                            for i in 0..MAX_ENTRIES {
                                if !TABLE[i].in_use {
                                    found = Some(i);
                                    break;
                                }
                            }
                        }
                        found
                    }
                };
                if let Some(i) = slot {
                    unsafe {
                        TABLE[i] = Entry {
                            in_use: true,
                            uuid,
                            method_mask,
                            port: svc_port,
                        };
                    }
                    let _ = syscall::reply(SVCREG_REGISTER_OK, i as u64, 0, 0, 0, 0);
                } else {
                    let _ = syscall::reply(SVCREG_REGISTER_FAIL, 0, 0, 0, 0, 0);
                }
            }
            SVCREG_UNREGISTER => {
                let uuid = uuid_from_words(msg.data[0], msg.data[1]);
                let caller_port = msg.data[2];
                if let Some(i) = find_by_uuid(&uuid) {
                    unsafe {
                        // Only the registrant can unregister.
                        if TABLE[i].port == caller_port {
                            TABLE[i] = Entry::empty();
                        }
                    }
                }
                let _ = syscall::reply(SVCREG_UNREGISTER_OK, 0, 0, 0, 0, 0);
            }
            SVCREG_LOOKUP => {
                let uuid = uuid_from_words(msg.data[0], msg.data[1]);
                let method = msg.data[2] as u32;
                let mask_bit = if method < 64 { 1u64 << method } else { 0 };
                let resolved = unsafe {
                    let mut hit = None;
                    for i in 0..MAX_ENTRIES {
                        if TABLE[i].in_use && TABLE[i].uuid == uuid
                            && (mask_bit == 0 || TABLE[i].method_mask & mask_bit != 0)
                        {
                            hit = Some(TABLE[i].port);
                            break;
                        }
                    }
                    hit
                };
                match resolved {
                    Some(p) => {
                        // Capability hint = 0 today; reserved for the
                        // attenuated capability bundle from piece (c).
                        let _ = syscall::reply(SVCREG_LOOKUP_OK, p, 0, 0, 0, 0);
                    }
                    None => {
                        let _ = syscall::reply(SVCREG_LOOKUP_NOTFOUND, 0, 0, 0, 0, 0);
                    }
                }
            }
            SVCREG_STATS => {
                let n = unsafe {
                    let mut c = 0u64;
                    for i in 0..MAX_ENTRIES {
                        if TABLE[i].in_use { c += 1; }
                    }
                    c
                };
                let _ = syscall::reply(SVCREG_STATS_OK, n, 0, 0, 0, 0);
            }
            _ => {
                let _ = syscall::reply(SVCREG_REGISTER_FAIL, 0, 0, 0, 0, 0);
            }
        }
    }
}

fn print_num(n: u64) {
    if n == 0 { syscall::debug_putchar(b'0'); return; }
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
