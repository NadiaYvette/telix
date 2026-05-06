//! discovery_srv — peer discovery for Tier 5 distributed bonding.
//!
//! First-cut implementation per docs/telix_distributed_strategy.md
//! (Tier 5).  Each Telix instance broadcasts a periodic announcement
//! identifying itself and the services it offers; receivers maintain
//! a peer table.  Cross-device IPC eventually piggy-backs on this
//! peer table to route requests to remote services.
//!
//! ## Wire protocol
//!
//! Direct Ethernet frames with a dedicated ethertype (0xD15C, "DISC").
//! Avoids needing an IPv4 stack with multicast support for the first
//! cut; can layer over IP later when discovery_srv goes onto a real
//! network instead of the QEMU virtual network.
//!
//! Payload layout (little-endian throughout):
//!
//!   offset 0:  magic = "TLXD" (0x44584C54 LE)         — 4 bytes
//!   offset 4:  version (1)                             — u16
//!   offset 6:  flags                                   — u16
//!   offset 8:  node_uuid                               — 16 bytes
//!   offset 24: timestamp_ns (sender's monotonic ns)    — u64
//!   offset 32: manifest_count                          — u8
//!   offset 33: reserved                                — 3 bytes
//!   offset 36: service_uuids [u8; 16][manifest_count]
//!
//! Maximum manifest is bounded by Ethernet MTU (1500) - 36 = 1464
//! bytes / 16 bytes per UUID = 91 service UUIDs.  Plenty for a
//! Telix instance's worth of services.
//!
//! ## RPC API (this crate's userlib::services counterpart)
//!
//! Tag space 0x4D00..0x4DFF reserved for discovery_srv.
//!
//!   DISCOVERY_LIST_PEERS (0x4D01)
//!     → DISCOVERY_LIST_PEERS_OK (0x4D02)
//!     data[0] = peer count
//!     For now, peer details are exposed via debug log only;
//!     a follow-up RPC will return per-peer info via grant.
//!
//!   DISCOVERY_GET_LOCAL_UUID (0x4D03)
//!     → DISCOVERY_GET_LOCAL_UUID_OK (0x4D04)
//!     data[0..2] = node_uuid (low / high 8 bytes)
//!
//! ## Status
//!
//! This skeleton lays out the state + RPC surface + announcement
//! marshalling.  Cross-device transmit/receive (NETIF_REGISTER for
//! ethertype 0xD15C, NETIF_XMIT for periodic broadcast, frame
//! callbacks for received announcements) lands in subsequent
//! commits.  Today it spawns, generates a node UUID, registers
//! with the name server, and serves the local-UUID RPC.

#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

// ---------------------------------------------------------------------------
// Wire protocol constants.
// ---------------------------------------------------------------------------

/// Ethertype reserved for Telix discovery announcements.  Distinct from
/// IPv4 (0x0800) and IPv6 (0x86dd) so the discovery channel doesn't
/// share bandwidth or filter logic with regular network traffic.
const _ETHERTYPE_DISCOVERY: u16 = 0xD15C;

/// Wire payload magic — "TLXD" little-endian.  Receivers reject any
/// frame whose payload starts with a different value, providing a
/// cheap sanity check before parsing the rest of the header.
const _DISCOVERY_MAGIC: u32 = 0x44584C54;

/// Current protocol version.  Receivers tolerate higher versions by
/// ignoring trailing fields (forward compat) but reject lower (because
/// older senders won't have the fields we read).
const _DISCOVERY_VERSION: u16 = 1;

/// How often (in milliseconds) we broadcast our own announcement.
/// 1 second is a reasonable starting cadence — frequent enough that a
/// freshly-booted peer is visible to others within a couple seconds,
/// rare enough that announcement traffic stays well under any
/// reasonable bandwidth budget.
const _ANNOUNCE_INTERVAL_MS: u64 = 1000;

/// How long a peer entry is considered live.  After this many
/// milliseconds without a fresh announcement, we evict.  3× the
/// announce interval handles single dropped frames; missing 3 in a
/// row is enough to call a peer dead.
const _PEER_TTL_MS: u64 = 3000;

// ---------------------------------------------------------------------------
// RPC tags.
// ---------------------------------------------------------------------------

const DISCOVERY_LIST_PEERS: u64 = 0x4D01;
const DISCOVERY_LIST_PEERS_OK: u64 = 0x4D02;
const DISCOVERY_GET_LOCAL_UUID: u64 = 0x4D03;
const DISCOVERY_GET_LOCAL_UUID_OK: u64 = 0x4D04;
const DISCOVERY_ERR: u64 = 0x4DFF;

// ---------------------------------------------------------------------------
// Peer table.
// ---------------------------------------------------------------------------

/// Maximum simultaneous tracked peers.  Linear scan; bump only when
/// fleet sizes warrant a hash table.
const MAX_PEERS: usize = 32;

/// Maximum services advertised per peer.  Matches typical Telix
/// service count (filesystem, network, graphics, etc).
const MAX_PEER_SERVICES: usize = 32;

#[derive(Copy, Clone)]
struct PeerEntry {
    in_use: bool,
    /// Identity bytes (16-byte UUID, opaque to discovery_srv).
    uuid: [u8; 16],
    /// Last time we saw an announcement from this peer (our local
    /// monotonic ns).  Used for TTL-based eviction.
    last_seen_ns: u64,
    /// Per-peer service-UUID list (content-addressed; cross-references
    /// servicereg_srv's UUID space).  Populated from announcement.
    service_uuids: [[u8; 16]; MAX_PEER_SERVICES],
    service_count: u8,
}

impl PeerEntry {
    const fn empty() -> Self {
        Self {
            in_use: false,
            uuid: [0; 16],
            last_seen_ns: 0,
            service_uuids: [[0; 16]; MAX_PEER_SERVICES],
            service_count: 0,
        }
    }
}

static mut PEERS: [PeerEntry; MAX_PEERS] = [PeerEntry::empty(); MAX_PEERS];

/// Our own identity, generated at startup from getrandom.  Stable for
/// the lifetime of this discovery_srv process; resets on restart
/// (peers will re-discover us under the new UUID).
static mut LOCAL_UUID: [u8; 16] = [0; 16];

fn count_active_peers() -> u64 {
    let mut n = 0u64;
    unsafe {
        for i in 0..MAX_PEERS {
            if PEERS[i].in_use {
                n += 1;
            }
        }
    }
    n
}

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

fn print_hex_byte(b: u8) {
    let hex = b"0123456789abcdef";
    syscall::debug_putchar(hex[(b >> 4) as usize]);
    syscall::debug_putchar(hex[(b & 0xF) as usize]);
}

fn print_uuid(u: &[u8; 16]) {
    for i in 0..16 {
        print_hex_byte(u[i]);
        if i == 3 || i == 5 || i == 7 || i == 9 {
            syscall::debug_putchar(b'-');
        }
    }
}

fn generate_local_uuid() {
    unsafe {
        let _ = syscall::getrandom((&raw mut LOCAL_UUID).cast::<u8>() as usize, 16);
        // Set RFC 4122 v4 markers (version 4, variant 1) — purely
        // cosmetic for now since the wire format treats UUIDs as
        // opaque, but it matches the convention services in the tree
        // use (e.g. services::ServiceUuid in userlib).
        LOCAL_UUID[6] = (LOCAL_UUID[6] & 0x0F) | 0x40;
        LOCAL_UUID[8] = (LOCAL_UUID[8] & 0x3F) | 0x80;
    }
}

#[unsafe(no_mangle)]
fn main(_a0: u64, _a1: u64, _a2: u64) {
    syscall::debug_puts(b"[discovery_srv] starting\n");

    generate_local_uuid();

    let port = syscall::port_create();
    if port == u64::MAX {
        syscall::debug_puts(b"[discovery_srv] port_create FAIL\n");
        syscall::exit(1);
    }
    if !syscall::ns_register(b"discovery", port) {
        syscall::debug_puts(b"[discovery_srv] ns_register FAIL\n");
        syscall::exit(1);
    }

    syscall::debug_puts(b"[discovery_srv] node_uuid=");
    unsafe {
        let u = &*(&raw const LOCAL_UUID);
        print_uuid(u);
    }
    syscall::debug_puts(b"\n");
    syscall::debug_puts(b"[discovery_srv] ready on port ");
    print_num(port);
    syscall::debug_puts(b"\n");

    // Future work: register with eth_srv via NETIF_REGISTER for
    // ethertype 0xD15C and start the announcement timer.  For now we
    // serve the synchronous RPC surface so callers can verify the
    // server is up + introspect the local UUID.

    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => continue,
        };
        match msg.tag {
            DISCOVERY_LIST_PEERS => {
                let n = count_active_peers();
                let _ = syscall::reply(DISCOVERY_LIST_PEERS_OK, n, 0, 0, 0, 0);
            }
            DISCOVERY_GET_LOCAL_UUID => {
                let (lo, hi) = unsafe {
                    let mut lo_bytes = [0u8; 8];
                    let mut hi_bytes = [0u8; 8];
                    lo_bytes.copy_from_slice(&LOCAL_UUID[0..8]);
                    hi_bytes.copy_from_slice(&LOCAL_UUID[8..16]);
                    (u64::from_le_bytes(lo_bytes), u64::from_le_bytes(hi_bytes))
                };
                let _ = syscall::reply(DISCOVERY_GET_LOCAL_UUID_OK, lo, hi, 0, 0, 0);
            }
            _ => {
                let _ = syscall::reply(DISCOVERY_ERR, 0, 0, 0, 0, 0);
            }
        }
    }
}
