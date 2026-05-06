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
const ETHERTYPE_DISCOVERY: u16 = 0xD15C;

/// Wire payload magic — "TLXD" little-endian.  Receivers reject any
/// frame whose payload starts with a different value, providing a
/// cheap sanity check before parsing the rest of the header.
const DISCOVERY_MAGIC: u32 = 0x44584C54;

/// Current protocol version.  Receivers tolerate higher versions by
/// ignoring trailing fields (forward compat) but reject lower (because
/// older senders won't have the fields we read).
const DISCOVERY_VERSION: u16 = 1;

/// How often (in milliseconds) we broadcast our own announcement.
/// 1 second is a reasonable starting cadence — frequent enough that a
/// freshly-booted peer is visible to others within a couple seconds,
/// rare enough that announcement traffic stays well under any
/// reasonable bandwidth budget.
const ANNOUNCE_INTERVAL_MS: u64 = 1000;

/// How long a peer entry is considered live.  After this many
/// milliseconds without a fresh announcement, we evict.  3× the
/// announce interval handles single dropped frames; missing 3 in a
/// row is enough to call a peer dead.
const _PEER_TTL_MS: u64 = 3000;

/// Minimum announcement payload size: header only, no service UUIDs.
const ANNOUNCE_HEADER_LEN: usize = 36;

// ---------------------------------------------------------------------------
// eth_srv interface (matches eth_srv NETIF protocol).
// ---------------------------------------------------------------------------
const NETIF_REGISTER: u64 = 0x5000;
const NETIF_REGISTER_OK: u64 = 0x5001;
const NETIF_XMIT: u64 = 0x5200;

// ---------------------------------------------------------------------------
// RPC tags.
// ---------------------------------------------------------------------------

const DISCOVERY_LIST_PEERS: u64 = 0x4D01;
const DISCOVERY_LIST_PEERS_OK: u64 = 0x4D02;
const DISCOVERY_GET_LOCAL_UUID: u64 = 0x4D03;
const DISCOVERY_GET_LOCAL_UUID_OK: u64 = 0x4D04;
/// Cumulative announcement broadcasts since startup.  Useful for
/// integration tests: the validator pings GET_STATS, sleeps briefly,
/// pings again, asserts the count went up — proves the announce
/// loop is firing without needing to capture network frames.
const DISCOVERY_GET_STATS: u64 = 0x4D05;
const DISCOVERY_GET_STATS_OK: u64 = 0x4D06;
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

/// Cached eth_srv port + tx state from NETIF_REGISTER handshake.
/// Zero / 0 / false until the handshake completes; broadcast becomes
/// a no-op until then so we don't crash if eth_srv isn't up yet.
static mut ETH_PORT: u64 = 0;
static mut ETH_TX_LOCAL_VA: usize = 0;
static mut ETH_TX_CLIENT_ID: u64 = 0;
static mut TX_REGISTERED: bool = false;
/// Counters surfaced to the boot log (and useful for cross-instance
/// validation later: peer A's announce_count should equal peer B's
/// frames_received_count modulo loss).
static mut ANNOUNCE_COUNT: u64 = 0;

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

/// Register with eth_srv for our discovery ethertype, allocating a tx
/// grant we can broadcast announcements through.  Best-effort: if
/// eth_srv isn't up yet, we just skip and broadcast becomes a no-op.
/// Modeled after nat_srv::try_register_eth_tx.
fn try_register_eth_tx(my_port: u64) {
    let eth_port = match syscall::ns_lookup(b"eth") {
        Some(p) => p,
        None => {
            syscall::debug_puts(
                b"  [discovery_srv] eth not registered; broadcast disabled\n",
            );
            return;
        }
    };
    unsafe { ETH_PORT = eth_port; }
    let local_tx = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [discovery_srv] mmap_anon for tx failed\n");
            return;
        }
    };
    // Pre-fault so the kernel grants a unique writable phys page to
    // eth_srv rather than the shared zero page.
    unsafe { core::ptr::write_volatile(local_tx as *mut u8, 0u8); }

    let reply_port = syscall::port_create();
    if reply_port == u64::MAX {
        syscall::debug_puts(b"  [discovery_srv] port_create for tx reply failed\n");
        return;
    }
    let _ = syscall::send_nb_4(
        eth_port,
        NETIF_REGISTER,
        ETHERTYPE_DISCOVERY as u64,
        my_port,
        reply_port,
        0,
    );
    let resp = syscall::recv_msg_timeout(reply_port, 2_000_000);
    let (cid, _eth_rx_va, eth_tx_va) = match resp {
        Some(m) if m.tag == NETIF_REGISTER_OK => {
            (m.data[0], m.data[1] as usize, m.data[2] as usize)
        }
        _ => {
            syscall::debug_puts(
                b"  [discovery_srv] NETIF_REGISTER handshake failed\n",
            );
            return;
        }
    };
    if !syscall::grant_pages(eth_port, local_tx, eth_tx_va, 1, false) {
        syscall::debug_puts(b"  [discovery_srv] grant_pages tx -> eth failed\n");
        return;
    }
    unsafe {
        ETH_TX_LOCAL_VA = local_tx;
        ETH_TX_CLIENT_ID = cid;
        TX_REGISTERED = true;
    }
    syscall::debug_puts(b"  [discovery_srv] eth tx registered (announce ready)\n");
}

/// Build the 36-byte announcement header into the granted tx page,
/// then send NETIF_XMIT to eth_srv with broadcast destination.
/// No-op when TX_REGISTERED is false (eth_srv handshake skipped).
fn broadcast_announcement() {
    unsafe {
        if !TX_REGISTERED || ETH_TX_LOCAL_VA == 0 || ETH_PORT == 0 {
            return;
        }
        // Layout (matches the wire-protocol comment at the top):
        //   0:  magic ("TLXD")               4 bytes
        //   4:  version                       u16
        //   6:  flags                         u16
        //   8:  node_uuid                     16 bytes
        //   24: timestamp_ns                  u64
        //   32: manifest_count                u8
        //   33: reserved                      3 bytes
        //   36: service_uuids[manifest_count] (none for now)
        let dst = ETH_TX_LOCAL_VA as *mut u8;
        // magic
        let mag = DISCOVERY_MAGIC.to_le_bytes();
        for i in 0..4 { core::ptr::write_volatile(dst.add(i), mag[i]); }
        // version + flags
        let ver = DISCOVERY_VERSION.to_le_bytes();
        let flg = 0u16.to_le_bytes();
        core::ptr::write_volatile(dst.add(4), ver[0]);
        core::ptr::write_volatile(dst.add(5), ver[1]);
        core::ptr::write_volatile(dst.add(6), flg[0]);
        core::ptr::write_volatile(dst.add(7), flg[1]);
        // node_uuid
        for i in 0..16 {
            core::ptr::write_volatile(dst.add(8 + i), LOCAL_UUID[i]);
        }
        // timestamp
        let ts = syscall::clock_gettime().to_le_bytes();
        for i in 0..8 {
            core::ptr::write_volatile(dst.add(24 + i), ts[i]);
        }
        // manifest_count + reserved
        core::ptr::write_volatile(dst.add(32), 0u8);
        for i in 0..3 {
            core::ptr::write_volatile(dst.add(33 + i), 0u8);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("mfence");

        // NETIF_XMIT data layout (matches eth_srv):
        //   data[0] = payload_len
        //   data[1] = dst_mac (0 = broadcast)
        //   data[2] = ethertype (low 16) | reply_port (high 32, unused)
        //   data[3] = client_id
        let _ = syscall::send_nb_4(
            ETH_PORT,
            NETIF_XMIT,
            ANNOUNCE_HEADER_LEN as u64,
            0u64, // broadcast
            ETHERTYPE_DISCOVERY as u64,
            ETH_TX_CLIENT_ID,
        );
        ANNOUNCE_COUNT += 1;
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

    // Register with eth_srv for our discovery ethertype + start the
    // announce loop.  Best-effort: if eth_srv isn't up the RPC surface
    // still works, just no broadcast.
    try_register_eth_tx(port);

    // Single-threaded main loop: receive RPCs with a timeout matching
    // the announce interval, broadcast on each timeout boundary.
    // Using clock_gettime as the source of truth so we don't drift
    // when an RPC arrives mid-interval.
    let mut last_announce_ns: u64 = 0;
    loop {
        let now_ns = syscall::clock_gettime();
        let elapsed_ms = (now_ns.wrapping_sub(last_announce_ns)) / 1_000_000;
        if elapsed_ms >= ANNOUNCE_INTERVAL_MS {
            broadcast_announcement();
            last_announce_ns = now_ns;
        }
        // Block at most until the next announce.  recv_msg_timeout takes
        // microseconds.  Floor at 1 ms so a backed-up announce
        // schedule doesn't pin a busy loop.
        let remaining_ms = ANNOUNCE_INTERVAL_MS.saturating_sub(elapsed_ms);
        let timeout_us = remaining_ms.max(1) * 1_000;
        let msg = syscall::recv_msg_timeout(port, timeout_us);
        let m = match msg {
            Some(m) => m,
            None => continue, // timeout — loop back to announce check
        };
        match m.tag {
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
            DISCOVERY_GET_STATS => {
                let n = unsafe { ANNOUNCE_COUNT };
                let tx_ready = unsafe { TX_REGISTERED } as u64;
                let _ = syscall::reply(
                    DISCOVERY_GET_STATS_OK,
                    n, tx_ready, 0, 0, 0,
                );
            }
            _ => {
                let _ = syscall::reply(DISCOVERY_ERR, 0, 0, 0, 0, 0);
            }
        }
    }
}
