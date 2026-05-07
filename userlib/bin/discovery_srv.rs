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
//!     in:  data[0] = grant_va in caller's aspace where peer records
//!                    should be written.  Caller must have already
//!                    grant_pages'd a page at that VA into our aspace.
//!                    Pass 0 to skip the payload write and only get the
//!                    count back (legacy form).
//!          data[1] = max_records the grant can hold (cap; caller-
//!                    supplied so we don't overrun whatever they
//!                    granted)
//!     out: DISCOVERY_LIST_PEERS_OK (0x4D02)
//!          data[0] = number of records actually written
//!          data[1] = total active peers (may exceed max_records)
//!
//!     Record layout (24 bytes each, contiguous at grant_va):
//!       bytes  0..16: uuid
//!       bytes 16..24: last_seen_ns (LE u64; sender's monotonic_ns
//!                     mapped through our local-monotonic at receive
//!                     time, so values are comparable across peers
//!                     within bounded clock-skew tolerance)
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
const PEER_TTL_MS: u64 = 3000;

/// Minimum announcement payload size: header only, no service UUIDs.
const ANNOUNCE_HEADER_LEN: usize = 36;

// ---------------------------------------------------------------------------
// eth_srv interface (matches eth_srv NETIF protocol).
// ---------------------------------------------------------------------------
const NETIF_REGISTER: u64 = 0x5000;
const NETIF_REGISTER_OK: u64 = 0x5001;
const NETIF_INPUT: u64 = 0x5100;  // eth_srv → client when a matching frame arrives
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

/// Cached eth_srv port + tx/rx state from NETIF_REGISTER handshake.
/// Zero / 0 / false until the handshake completes; broadcast becomes
/// a no-op until then so we don't crash if eth_srv isn't up yet.
static mut ETH_PORT: u64 = 0;
static mut ETH_TX_LOCAL_VA: usize = 0;
static mut ETH_RX_LOCAL_VA: usize = 0;
static mut ETH_TX_CLIENT_ID: u64 = 0;
static mut TX_REGISTERED: bool = false;

/// Cached servicereg_srv port + scratch page where we serialize the
/// list of locally-registered service UUIDs.  Zero until the first
/// successful ns_lookup("servicereg").  Refreshed every announce
/// (1 Hz) so newly-registered services land in the next broadcast.
static mut SVCREG_PORT: u64 = 0;
static mut SVCREG_SCRATCH_VA: usize = 0;
/// Number of UUIDs currently in SVCREG_SCRATCH_VA, ≤ MAX_LOCAL_SVCS.
static mut LOCAL_SVC_COUNT: u8 = 0;

/// Cap on services advertised in our announcement.  Bounded by what
/// fits in one Ethernet MTU after the 36-byte header (1500 - 36) / 16
/// = 91, but our scratch page (4 KiB / 16 = 256) is the tighter
/// constraint after we cap at 64 here for parity with eth_srv MTU
/// math and to keep the scratch pre-fault simple.
const MAX_LOCAL_SVCS: usize = 64;
/// Counters surfaced to the boot log (and useful for cross-instance
/// validation later: peer A's announce_count should equal peer B's
/// frames_received_count modulo loss).
static mut ANNOUNCE_COUNT: u64 = 0;
static mut FRAMES_RECEIVED_COUNT: u64 = 0;
static mut FRAMES_REJECTED_COUNT: u64 = 0;
static mut PEER_INSERT_COUNT: u64 = 0;
static mut PEER_EVICT_COUNT: u64 = 0;

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

/// Handle a NETIF_INPUT notification: parse the announcement at
/// ETH_RX_LOCAL_VA, validate, then upsert the sender in PEERS.
/// Silently drops malformed frames (counted in FRAMES_REJECTED_COUNT)
/// — discovery is best-effort by design.
fn handle_netif_input(payload_len: usize) {
    unsafe {
        FRAMES_RECEIVED_COUNT += 1;
        if ETH_RX_LOCAL_VA == 0 {
            FRAMES_REJECTED_COUNT += 1;
            return;
        }
        if payload_len < ANNOUNCE_HEADER_LEN {
            FRAMES_REJECTED_COUNT += 1;
            return;
        }
        let buf = ETH_RX_LOCAL_VA as *const u8;
        // Read header fields (LE).
        let mut magic_bytes = [0u8; 4];
        for i in 0..4 { magic_bytes[i] = core::ptr::read_volatile(buf.add(i)); }
        let magic = u32::from_le_bytes(magic_bytes);
        if magic != DISCOVERY_MAGIC {
            FRAMES_REJECTED_COUNT += 1;
            return;
        }
        let mut ver_bytes = [0u8; 2];
        ver_bytes[0] = core::ptr::read_volatile(buf.add(4));
        ver_bytes[1] = core::ptr::read_volatile(buf.add(5));
        let ver = u16::from_le_bytes(ver_bytes);
        if ver < DISCOVERY_VERSION {
            // Older sender than us; we'd be missing fields they don't
            // have.  Reject rather than misparse.
            FRAMES_REJECTED_COUNT += 1;
            return;
        }
        // Skip flags (offset 6, 2 bytes).
        // node_uuid at offset 8.
        let mut uuid = [0u8; 16];
        for i in 0..16 { uuid[i] = core::ptr::read_volatile(buf.add(8 + i)); }
        // Reject our own announcement (loopback).  When eth_srv hairpins
        // a broadcast back to all clients including the sender we'd
        // otherwise insert ourselves as a peer.
        if uuid == LOCAL_UUID {
            return;
        }
        // Skip timestamp_ns (offset 24, 8 bytes) — not currently consumed.
        let manifest_count = core::ptr::read_volatile(buf.add(32)) as usize;
        // Bound manifest_count to what fits in the rest of the payload
        // AND our per-peer storage.
        let max_from_payload = (payload_len - ANNOUNCE_HEADER_LEN) / 16;
        let svc_count = manifest_count.min(MAX_PEER_SERVICES).min(max_from_payload);

        // Find existing slot or insert new.
        let now_ns = syscall::clock_gettime();
        let mut slot: Option<usize> = None;
        for i in 0..MAX_PEERS {
            if PEERS[i].in_use && PEERS[i].uuid == uuid {
                slot = Some(i);
                break;
            }
        }
        let idx = match slot {
            Some(i) => i,
            None => {
                // Linear scan for free slot.  Full table → drop the
                // announcement; eviction in maintain_peer_table will
                // free space at the next interval.
                let mut found: Option<usize> = None;
                for i in 0..MAX_PEERS {
                    if !PEERS[i].in_use {
                        found = Some(i);
                        break;
                    }
                }
                match found {
                    Some(i) => {
                        PEERS[i].in_use = true;
                        PEERS[i].uuid = uuid;
                        PEER_INSERT_COUNT += 1;
                        i
                    }
                    None => {
                        FRAMES_REJECTED_COUNT += 1;
                        return;
                    }
                }
            }
        };

        PEERS[idx].last_seen_ns = now_ns;
        // Copy service UUIDs from offset 36 onward.
        PEERS[idx].service_count = svc_count as u8;
        for s in 0..svc_count {
            for b in 0..16 {
                PEERS[idx].service_uuids[s][b] =
                    core::ptr::read_volatile(buf.add(36 + s * 16 + b));
            }
        }
    }
}

/// Serialize active PEERS into the caller's grant page at grant_va.
/// Returns the number of records actually written (capped at
/// max_records).  Layout per record (24 bytes contiguous):
///   bytes  0..16: uuid
///   bytes 16..24: last_seen_ns (LE u64)
fn write_peer_records(grant_va: usize, max_records: usize) -> usize {
    const RECORD_SIZE: usize = 24;
    let mut written = 0usize;
    unsafe {
        let dst_base = grant_va as *mut u8;
        for i in 0..MAX_PEERS {
            if !PEERS[i].in_use {
                continue;
            }
            if written >= max_records {
                break;
            }
            let off = written * RECORD_SIZE;
            // uuid
            for b in 0..16 {
                core::ptr::write_volatile(dst_base.add(off + b), PEERS[i].uuid[b]);
            }
            // last_seen_ns
            let ts = PEERS[i].last_seen_ns.to_le_bytes();
            for b in 0..8 {
                core::ptr::write_volatile(dst_base.add(off + 16 + b), ts[b]);
            }
            written += 1;
        }
        // Release fence so the receiver (caller's CPU) sees our writes
        // before observing the reply.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    }
    written
}

/// Sweep PEERS, evicting entries whose last_seen_ns is older than
/// PEER_TTL_MS.  Called once per main-loop tick — the linear scan is
/// O(MAX_PEERS) so cost is bounded.
fn maintain_peer_table(now_ns: u64) {
    let ttl_ns = PEER_TTL_MS * 1_000_000;
    unsafe {
        for i in 0..MAX_PEERS {
            if PEERS[i].in_use {
                let age = now_ns.wrapping_sub(PEERS[i].last_seen_ns);
                if age > ttl_ns {
                    PEERS[i] = PeerEntry::empty();
                    PEER_EVICT_COUNT += 1;
                }
            }
        }
    }
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
/// grant we can broadcast announcements through *and* an rx grant
/// where eth_srv will deposit incoming discovery-ethertype frames.
/// Best-effort: if eth_srv isn't up yet, we just skip and broadcast
/// + receive both become no-ops.  Modeled after nat_srv's pattern.
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
    // Allocate two anon pages: one for tx (we write announcement, eth_srv
    // reads & sends), one for rx (eth_srv writes incoming payload, we
    // read & parse).
    let local_tx = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [discovery_srv] mmap_anon for tx failed\n");
            return;
        }
    };
    let local_rx = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [discovery_srv] mmap_anon for rx failed\n");
            return;
        }
    };
    // Pre-fault both so the kernel grants unique writable phys pages
    // (rather than the shared zero page) before the grant_pages calls.
    unsafe {
        core::ptr::write_volatile(local_tx as *mut u8, 0u8);
        core::ptr::write_volatile(local_rx as *mut u8, 0u8);
    }

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
    let (cid, eth_rx_va, eth_tx_va) = match resp {
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
    if !syscall::grant_pages(eth_port, local_rx, eth_rx_va, 1, false) {
        syscall::debug_puts(b"  [discovery_srv] grant_pages rx -> eth failed\n");
        return;
    }
    unsafe {
        ETH_TX_LOCAL_VA = local_tx;
        ETH_RX_LOCAL_VA = local_rx;
        ETH_TX_CLIENT_ID = cid;
        TX_REGISTERED = true;
    }
    syscall::debug_puts(
        b"  [discovery_srv] eth tx+rx registered (announce + receive ready)\n",
    );
}

// servicereg_srv RPC tags — must match servicereg_srv.rs.  We pin them
// here rather than importing because servicereg_srv exports them as
// `pub const` on a binary crate, and binaries can't depend on each
// other directly.  Drift is caught at runtime: a wrong tag returns
// SVCREG_REGISTER_FAIL (0x7E0F) and we count it as a query failure.
const SVCREG_LIST_UUIDS: u64 = 0x7E22;
const SVCREG_LIST_UUIDS_OK: u64 = 0x7E23;

/// Lazy-resolve servicereg_srv's port and allocate a scratch page
/// where we'll cache its UUID list.  Best-effort; if servicereg_srv
/// isn't up yet we'll retry on the next announce tick.
fn ensure_svcreg() {
    unsafe {
        if SVCREG_PORT == 0 {
            if let Some(p) = syscall::ns_lookup(b"servicereg") {
                SVCREG_PORT = p;
            } else {
                return;
            }
        }
        if SVCREG_SCRATCH_VA == 0 {
            if let Some(va) = syscall::mmap_anon(0, 1, 1) {
                core::ptr::write_volatile(va as *mut u8, 0u8);
                SVCREG_SCRATCH_VA = va;
            }
        }
    }
}

/// Refresh the cached LOCAL_SVCS list from servicereg_srv.  Called
/// once per announce tick; one syscall + one IPC round-trip, bounded
/// cost.
fn refresh_local_svcs() {
    ensure_svcreg();
    unsafe {
        if SVCREG_PORT == 0 || SVCREG_SCRATCH_VA == 0 {
            LOCAL_SVC_COUNT = 0;
            return;
        }
        // Per piece (b) of project_personality_vm_layout_abi note:
        // pass the scratch_va in our aspace; servicereg_srv writes
        // there because we'll also want to grant_pages it once at
        // setup time.  No grant yet — servicereg_srv currently
        // expects the va in its own aspace, which means we need to
        // grant once before the first call.  Lazily set up here.
    }
    // Grant scratch into servicereg_srv's aspace once.  Subsequent
    // calls reuse the grant.
    static mut GRANTED: bool = false;
    unsafe {
        if !GRANTED && SVCREG_PORT != 0 && SVCREG_SCRATCH_VA != 0 {
            // Reuse a per-server grant_va we choose.  Pick a value
            // distinct from other servers to avoid the unchecked-deref
            // shape from project_storage_srv_efi_part_pf.md.
            const GRANT_VA: usize = 0x9_0000_0000;
            // svcreg_srv resolves grant_va from our msg payload, so
            // we encode it into msg.data[0] of SVCREG_LIST_UUIDS;
            // the actual grant must already be in place when the
            // server reads.
            if syscall::grant_pages(SVCREG_PORT, SVCREG_SCRATCH_VA, GRANT_VA, 1, false) {
                GRANTED = true;
            } else {
                return;
            }
        }
        if !GRANTED {
            return;
        }
        const GRANT_VA: usize = 0x9_0000_0000;
        let resp = syscall::call(
            SVCREG_PORT,
            SVCREG_LIST_UUIDS,
            GRANT_VA as u64,
            MAX_LOCAL_SVCS as u64,
            0, 0,
        );
        match resp {
            Some(m) if m.tag == SVCREG_LIST_UUIDS_OK => {
                let n = (m.data[0] as usize).min(MAX_LOCAL_SVCS);
                LOCAL_SVC_COUNT = n as u8;
            }
            _ => {
                // Leave previous count in place.  Next tick retries.
            }
        }
    }
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
        // manifest_count + reserved.  manifest_count is written below
        // after we copy the UUIDs in (so we can use the source-of-truth
        // count post-cap rather than the value we promised).
        for i in 0..3 {
            core::ptr::write_volatile(dst.add(33 + i), 0u8);
        }

        // Manifest: copy LOCAL_SVC_COUNT × 16-byte UUIDs from
        // SVCREG_SCRATCH_VA (filled by refresh_local_svcs at announce
        // time) into bytes [36, 36 + 16*N) of the announcement.
        // Bounds: cap at MAX_LOCAL_SVCS and at MTU - 36 to fit one
        // Ethernet frame.
        let mut svc_count = LOCAL_SVC_COUNT as usize;
        if svc_count > MAX_LOCAL_SVCS {
            svc_count = MAX_LOCAL_SVCS;
        }
        // Don't blow the 1500-byte MTU: 36 header + 16 per UUID.
        let max_by_mtu = (1500 - ANNOUNCE_HEADER_LEN) / 16;
        if svc_count > max_by_mtu {
            svc_count = max_by_mtu;
        }
        if svc_count > 0 && SVCREG_SCRATCH_VA != 0 {
            let svc_src = SVCREG_SCRATCH_VA as *const u8;
            for i in 0..(svc_count * 16) {
                core::ptr::write_volatile(
                    dst.add(36 + i),
                    core::ptr::read_volatile(svc_src.add(i)),
                );
            }
        }
        core::ptr::write_volatile(dst.add(32), svc_count as u8);

        let payload_len = ANNOUNCE_HEADER_LEN + svc_count * 16;

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
            payload_len as u64,
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

    // Single-threaded main loop: receive RPCs in a polling shape that
    // ALSO triggers periodic broadcasts when the announce interval
    // elapses.  recv_with_cap_nb (not recv_msg_timeout) is critical:
    // the latter doesn't install the held_reply_cap that syscall::reply
    // needs, so any RPC received via the timeout variant would fail to
    // reply (caller hangs, then times out).  Use the cap-aware
    // non-blocking variant in a sleep_ms-paced loop so RPCs reply
    // correctly and the announce timer advances.
    let mut last_announce_ns: u64 = 0;
    loop {
        let now_ns = syscall::clock_gettime();
        let elapsed_ms = (now_ns.wrapping_sub(last_announce_ns)) / 1_000_000;
        if elapsed_ms >= ANNOUNCE_INTERVAL_MS {
            refresh_local_svcs();
            broadcast_announcement();
            maintain_peer_table(now_ns);
            last_announce_ns = now_ns;
        }
        // Drain any queued RPCs / NETIF_INPUT notifications.  Each
        // iteration handles one if present; the outer loop continues
        // if none.
        let m = match syscall::recv_with_cap_nb(port) {
            Some(m) => m,
            None => {
                // No message; idle until a few ms before the next
                // announce boundary, then loop back.  A 10 ms slice
                // bounds RPC + frame-arrival latency without busy-
                // waiting.
                syscall::sleep_ms(10);
                continue;
            }
        };
        match m.tag {
            NETIF_INPUT => {
                // eth_srv delivered a discovery-ethertype frame.
                // data[0] = payload_len, data[1] = src_mac (unused).
                handle_netif_input(m.data[0] as usize);
                // No reply needed — NETIF_INPUT is a notification,
                // not a call.
            }
            DISCOVERY_LIST_PEERS => {
                let grant_va = m.data[0] as usize;
                let max_records = m.data[1] as usize;
                let total = count_active_peers();
                let written = if grant_va == 0 || max_records == 0 {
                    0u64
                } else {
                    write_peer_records(grant_va, max_records) as u64
                };
                let _ = syscall::reply(
                    DISCOVERY_LIST_PEERS_OK,
                    written, total, 0, 0, 0,
                );
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
                // data[0]: announce_count
                // data[1]: tx_ready (1 if NETIF_REGISTER completed)
                // data[2]: frames_received_count
                // data[3]: peer_insert_count - peer_evict_count
                //          (currently-live insertions; equals
                //          count_active_peers() under steady state)
                let (n, tx_ready, rx_n, live) = unsafe {
                    (
                        ANNOUNCE_COUNT,
                        TX_REGISTERED as u64,
                        FRAMES_RECEIVED_COUNT,
                        PEER_INSERT_COUNT.wrapping_sub(PEER_EVICT_COUNT),
                    )
                };
                let _ = syscall::reply(
                    DISCOVERY_GET_STATS_OK,
                    n, tx_ready, rx_n, live, 0,
                );
            }
            _ => {
                let _ = syscall::reply(DISCOVERY_ERR, 0, 0, 0, 0, 0);
            }
        }
    }
}
