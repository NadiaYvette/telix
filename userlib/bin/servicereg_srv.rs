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

/// Enumerate registered service UUIDs.  Caller must have grant_pages'd
/// a page at `grant_va` into our aspace; we serialize active entries'
/// UUIDs (16 bytes each, contiguous) into it, capped at `max_records`.
/// Reply data[0] = number actually written, data[1] = total registered
/// (so the caller can detect a too-small grant).
///
/// Used by discovery_srv to populate the manifest of its outgoing
/// announcement frames.
pub const SVCREG_LIST_UUIDS: u64 = 0x7E22;
pub const SVCREG_LIST_UUIDS_OK: u64 = 0x7E23;

/// Look up a service that may be registered on a *remote* peer.
/// Local table is searched first; on miss we delegate to discovery_srv
/// (DISCOVERY_LOOKUP_SERVICE, 0x4D09) and forward its answer.
///
/// in:  data[0..2] = UUID (LE-packed two u64 words; same shape as
///                   SVCREG_LOOKUP)
/// out:
///   SVCREG_LOOKUP_OK (0x7E11) — local hit; data[0] = port,
///                                 data[1] = bundle (same as SVCREG_LOOKUP)
///   SVCREG_LOOKUP_REMOTE_OK    — remote peer offers it;
///                                 data[0..2] = peer UUID
///                                 data[2]    = last_seen_ns
///   SVCREG_LOOKUP_NOTFOUND     — neither local nor any peer has it
///
/// Caller policy: on REMOTE_OK, hand the peer UUID to proxy_srv (or
/// future name-server-backed forwarding) to obtain a routable port.
pub const SVCREG_LOOKUP_REMOTE: u64 = 0x7E24;
pub const SVCREG_LOOKUP_REMOTE_OK: u64 = 0x7E25;

/// Maximum simultaneous registrations.
const MAX_ENTRIES: usize = 64;

#[derive(Copy, Clone)]
struct Entry {
    in_use: bool,
    uuid: [u8; 16],
    method_mask: u32,
    bundle: u32,
    port: u64,
}

impl Entry {
    const fn empty() -> Self {
        Self {
            in_use: false,
            uuid: [0; 16],
            method_mask: 0,
            bundle: 0,
            port: 0,
        }
    }
}

static mut TABLE: [Entry; MAX_ENTRIES] = [Entry::empty(); MAX_ENTRIES];

/// Cached discovery_srv port — lazy-resolved at first SVCREG_LOOKUP_REMOTE.
/// 0 = not yet looked up; u64::MAX = looked up and found nothing
/// (don't keep retrying every call).
static mut DISCOVERY_PORT: u64 = 0;

const DISCOVERY_LOOKUP_SERVICE: u64 = 0x4D09;
const DISCOVERY_LOOKUP_SERVICE_OK: u64 = 0x4D0A;

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
                // Wire format: low 32 bits of data[2] = method_mask,
                // high 32 bits = capability bundle.  See
                // userlib::services::register for the rationale.
                let method_mask = (msg.data[2] & 0xFFFF_FFFF) as u32;
                let bundle = ((msg.data[2] >> 32) & 0xFFFF_FFFF) as u32;
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
                            bundle,
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
                let mask_bit: u32 = if method < 32 { 1u32 << method } else { 0 };
                let resolved: Option<(u64, u32)> = unsafe {
                    let mut hit: Option<(u64, u32)> = None;
                    for i in 0..MAX_ENTRIES {
                        if TABLE[i].in_use && TABLE[i].uuid == uuid
                            && (mask_bit == 0 || TABLE[i].method_mask & mask_bit != 0)
                        {
                            hit = Some((TABLE[i].port, TABLE[i].bundle));
                            break;
                        }
                    }
                    hit
                };
                match resolved {
                    Some((p, bundle)) => {
                        // Piece (c): capability_hint slot now carries
                        // the bundle the caller's session is authorised
                        // under.  Bundle is u32 on the wire (packed
                        // alongside method_mask in register), widened
                        // back to u64 here for the caller's
                        // convenience and forward compatibility.
                        let _ = syscall::reply(
                            SVCREG_LOOKUP_OK,
                            p,
                            bundle as u64,
                            0, 0, 0,
                        );
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
            SVCREG_LOOKUP_REMOTE => {
                let uuid = uuid_from_words(msg.data[0], msg.data[1]);
                // 1. Try local first (any-method match — bundle is
                //    irrelevant for the remote-routing case).
                let local: Option<(u64, u32)> = unsafe {
                    let mut hit: Option<(u64, u32)> = None;
                    for i in 0..MAX_ENTRIES {
                        if TABLE[i].in_use && TABLE[i].uuid == uuid {
                            hit = Some((TABLE[i].port, TABLE[i].bundle));
                            break;
                        }
                    }
                    hit
                };
                if let Some((p, bundle)) = local {
                    let _ = syscall::reply(SVCREG_LOOKUP_OK, p, bundle as u64, 0, 0, 0);
                    continue;
                }
                // 2. No local match — ask discovery_srv.
                let disc_port = unsafe {
                    if DISCOVERY_PORT == 0 {
                        match syscall::ns_lookup(b"discovery") {
                            Some(p) => { DISCOVERY_PORT = p; p }
                            None => { DISCOVERY_PORT = u64::MAX; u64::MAX }
                        }
                    } else {
                        DISCOVERY_PORT
                    }
                };
                if disc_port == u64::MAX {
                    let _ = syscall::reply(SVCREG_LOOKUP_NOTFOUND, 0, 0, 0, 0, 0);
                    continue;
                }
                match syscall::call(disc_port, DISCOVERY_LOOKUP_SERVICE,
                                    msg.data[0], msg.data[1], 0, 0) {
                    Some(r) if r.tag == DISCOVERY_LOOKUP_SERVICE_OK => {
                        let _ = syscall::reply(
                            SVCREG_LOOKUP_REMOTE_OK,
                            r.data[0], r.data[1], r.data[2], 0, 0,
                        );
                    }
                    _ => {
                        let _ = syscall::reply(SVCREG_LOOKUP_NOTFOUND, 0, 0, 0, 0, 0);
                    }
                }
            }
            SVCREG_LIST_UUIDS => {
                let grant_va = msg.data[0] as usize;
                let max_records = msg.data[1] as usize;
                let mut written = 0usize;
                let mut total = 0u64;
                unsafe {
                    for i in 0..MAX_ENTRIES {
                        if TABLE[i].in_use {
                            total += 1;
                            if grant_va != 0 && written < max_records {
                                let dst = (grant_va + written * 16) as *mut u8;
                                for b in 0..16 {
                                    core::ptr::write_volatile(dst.add(b), TABLE[i].uuid[b]);
                                }
                                written += 1;
                            }
                        }
                    }
                    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
                }
                let _ = syscall::reply(
                    SVCREG_LIST_UUIDS_OK,
                    written as u64, total, 0, 0, 0,
                );
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
