//! nat_srv — NAT44 source-NAT engine + protocol surface for NAT64.
//!
//! Self-contained translation engine: callers pass packet bytes via grant,
//! the server rewrites and returns the translated packet plus checksums.
//! No forwarding-plane integration yet — that's a separate piece of work
//! that wires nat_srv into traffic flow between eth_srv and the existing
//! socket servers.  Until then, nat_srv is unit-testable in isolation:
//! a test client constructs a synthetic IP packet, calls
//! NAT_TRANSLATE_OUT / NAT_TRANSLATE_IN, and verifies the rewrite.
//!
//! NAT44 source-NAT:
//!   Outbound: rewrite (src_ip, src_port) of an IPv4 TCP/UDP packet to
//!   our public IP + an allocated port; remember the mapping in a flow
//!   table.  Recompute IPv4 + L4 checksums.
//!   Inbound: look up the flow table by (proto, dst_port); rewrite
//!   (dst_ip, dst_port) back to the original (src_ip, src_port).
//!
//! NAT64 stateful (RFC 6146): protocol surface preserved (the
//! NAT_TRANSLATE_V6_TO_V4 / NAT_TRANSLATE_V4_TO_V6 ops still
//! return ERR_NOT_IMPLEMENTED) — the engine landing here covers
//! only the NAT44 case.  NAT64 adds IPv6 header parsing + the
//! well-known prefix lookup; same flow-table machinery applies.
//!
//! Service name: registered as b"nat".

#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

// ---------------------------------------------------------------------------
// Message protocol.  Tags in the 0x7C range to avoid colliding with the
// other servers (uds 0x80, irfs 0x10x, ...).
// ---------------------------------------------------------------------------

/// Configure the NAT64 well-known prefix (default 64:ff9b::/96 per
/// RFC 6052).  Currently a stub — NAT64 packet rewrite isn't
/// implemented yet.
pub const NAT_SET_NAT64_PREFIX: u64 = 0x7C01;
pub const NAT_SET_NAT64_PREFIX_OK: u64 = 0x7C02;

/// Configure the public IPv4 address used for NAT44 source-NAT.
/// data[0] = ipv4 address, big-endian u32 in low 32 bits.
pub const NAT_SET_PUBLIC_IPV4: u64 = 0x7C05;
pub const NAT_SET_PUBLIC_IPV4_OK: u64 = 0x7C06;

/// Static port-forward (NAT44 inbound).  Stub for now.
pub const NAT_PORTFORWARD_ADD: u64 = 0x7C10;
pub const NAT_PORTFORWARD_ADD_OK: u64 = 0x7C11;
pub const NAT_PORTFORWARD_DEL: u64 = 0x7C12;
pub const NAT_PORTFORWARD_DEL_OK: u64 = 0x7C13;

/// Outbound translate.  Caller passes the packet via a previously-
/// granted scratch buffer at NAT_SCRATCH_VA in our aspace.
/// data[0] = packet length in bytes (max NAT_MAX_PACKET).
/// On reply, data[0] = translated packet length (caller copies out
/// of the same scratch).  data[1] = allocated public port (for
/// NAT44 source-NAT).  data[2] = error code if any.
pub const NAT_TRANSLATE_OUT: u64 = 0x7C30;
pub const NAT_TRANSLATE_OUT_OK: u64 = 0x7C31;

/// Inbound translate (reply for a prior outbound).
pub const NAT_TRANSLATE_IN: u64 = 0x7C32;
pub const NAT_TRANSLATE_IN_OK: u64 = 0x7C33;

/// Legacy NAT64-specific ops — protocol surface preserved, not yet
/// implemented.
pub const NAT_TRANSLATE_V6_TO_V4: u64 = 0x7C20;
pub const NAT_TRANSLATE_V6_TO_V4_OK: u64 = 0x7C21;
pub const NAT_TRANSLATE_V4_TO_V6: u64 = 0x7C22;
pub const NAT_TRANSLATE_V4_TO_V6_OK: u64 = 0x7C23;

/// Statistics.  Returns flow-table occupancy + counters.
pub const NAT_STATS: u64 = 0x7C40;
pub const NAT_STATS_OK: u64 = 0x7C41;

pub const NAT_ERR: u64 = 0x7CFF;
pub const ERR_NOT_IMPLEMENTED: u64 = 1;
pub const ERR_PACKET_TOO_SHORT: u64 = 2;
pub const ERR_NOT_IPV4: u64 = 3;
pub const ERR_UNSUPPORTED_PROTO: u64 = 4;
pub const ERR_FLOW_TABLE_FULL: u64 = 5;
pub const ERR_NO_FLOW: u64 = 6;
pub const ERR_NOT_CONFIGURED: u64 = 7;

/// Caller stages packet bytes here, then calls NAT_TRANSLATE_*.  This
/// is a convention — the actual grant setup is the caller's
/// responsibility (using grant_pages_lease against this VA).
pub const NAT_SCRATCH_VA: usize = 0x4_0000_0000;

const NAT_MAX_PACKET: usize = 1500;

// ---------------------------------------------------------------------------
// Forwarding-plane auto-subscription (Piece a + b convergence).
// nat_srv subscribes to non-local IPv4 frames via eth_srv's
// ETH_SUBSCRIBE protocol on startup; arriving frames feed directly
// into the translate_out engine without requiring explicit caller
// orchestration.  This is the first end-to-end use of the
// forwarding-plane substrate to compose two real services.
// ---------------------------------------------------------------------------

/// VA where eth_srv's RX page is granted into our aspace for the
/// auto-translate flow.  Distinct from NAT_SCRATCH_VA so the explicit
/// caller-driven path and the auto-subscription path don't fight over
/// the same buffer.
const ETH_RX_VA: usize = 0x4_0001_0000;

const ETH_HDR_LEN: usize = 14;

// ETH_SUBSCRIBE protocol (matches eth_srv).
const ETH_SUBSCRIBE: u64 = 0x5500;
const ETH_SUBSCRIBE_OK: u64 = 0x5501;
const ETH_FRAME: u64 = 0x5520;
const ETHERTYPE_IPV4: u16 = 0x0800;
const FILTER_FLAG_NON_LOCAL: u64 = 1 << 0;

// NETIF_REGISTER / NETIF_XMIT / NETIF_RESOLVE (matches eth_srv).
// We register with a placeholder ethertype (0xFFFE — IEEE-reserved,
// won't appear on real frames) just to obtain a tx_grant_va;
// tcp4_srv keeps the legitimate ownership of 0x0800 for RX dispatch.
// RX delivery to us still flows through ETH_SUBSCRIBE, not through
// the legacy NETIF_INPUT path.
const NETIF_REGISTER: u64 = 0x5000;
const NETIF_REGISTER_OK: u64 = 0x5001;
const NETIF_XMIT: u64 = 0x5200;
const NETIF_RESOLVE: u64 = 0x5300;
const NETIF_RESOLVE_OK: u64 = 0x5301;
const NETIF_XMIT_PLACEHOLDER_ETHERTYPE: u16 = 0xFFFE;

/// Gateway IP for ARP resolution.  Matches eth_srv's GATEWAY_IP.
/// QEMU user-mode default is 10.0.2.2.  In a real deployment this
/// would come from configuration or DHCP.
const GATEWAY_IPV4: u32 = 0x0A00_0202; // 10.0.2.2

/// RFC 5737 documentation/test address used as the default public
/// IPv4 for source-NAT, so translation still does something
/// observable even before NAT_SET_PUBLIC_IPV4 is called explicitly.
/// 192.0.2.1 = 0xC0000201 in network byte order.
const DEFAULT_PUBLIC_IPV4: u32 = 0xC000_0201;

// IPv4 + TCP/UDP constants.
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

const FLOW_TABLE_SIZE: usize = 256;
/// Public-port pool: ephemeral range per RFC 6056.  We allocate
/// sequentially from this pool; on wrap, we recycle expired flows.
const PUBLIC_PORT_BASE: u16 = 49152;
const PUBLIC_PORT_END: u16 = 65535;

// ---------------------------------------------------------------------------
// Flow table.  Indexed by (proto, public_port) for inbound lookup;
// linear-scanned by (proto, src_ip, src_port) for outbound lookup.
// ---------------------------------------------------------------------------

#[derive(Copy, Clone)]
struct FlowEntry {
    in_use: bool,
    proto: u8,
    /// Original private-side source.
    private_ip: u32,
    private_port: u16,
    /// Allocated public-side source port (we use the configured
    /// public IPv4 globally, so we don't store it per-flow).
    public_port: u16,
}

impl FlowEntry {
    const fn empty() -> Self {
        Self {
            in_use: false,
            proto: 0,
            private_ip: 0,
            private_port: 0,
            public_port: 0,
        }
    }
}

static mut FLOW_TABLE: [FlowEntry; FLOW_TABLE_SIZE] =
    [FlowEntry::empty(); FLOW_TABLE_SIZE];

/// Configured public IPv4 for source-NAT (host byte order).
/// 0 means unconfigured — NAT_TRANSLATE_OUT returns ERR_NOT_CONFIGURED.
static mut PUBLIC_IPV4: u32 = 0;

/// Monotonic next public-port allocator.
static mut NEXT_PUBLIC_PORT: u16 = PUBLIC_PORT_BASE;

/// Counters surfaced by NAT_STATS.
static mut TRANSLATED_OUT_COUNT: u64 = 0;
static mut TRANSLATED_IN_COUNT: u64 = 0;
static mut DROPPED_COUNT: u64 = 0;
/// Frames received via ETH_SUBSCRIBE auto-translate path.  Increment
/// regardless of whether translation succeeded — the SUBSCRIBED_*
/// counters give visibility into how much traffic the forwarding-plane
/// dispatch actually delivered.
static mut SUBSCRIBED_FRAMES_COUNT: u64 = 0;
static mut SUBSCRIBED_TRANSLATED_COUNT: u64 = 0;
static mut SUBSCRIBED_DROPPED_COUNT: u64 = 0;
/// Frames re-emitted via NETIF_XMIT after successful translation.
/// Distinct from SUBSCRIBED_TRANSLATED_COUNT because translate_out can
/// succeed even if the egress copy or NETIF_XMIT fails.
static mut SUBSCRIBED_EMITTED_COUNT: u64 = 0;
/// True once ETH_SUBSCRIBE handshake completed at startup.  Surfaced
/// in NAT_STATS so callers can confirm the substrate wired up.
static mut SUBSCRIBED: bool = false;
/// True once NETIF_REGISTER handshake completed and tx grant is in
/// place.  Egress is gated on this — translate_out runs even if
/// egress isn't ready, but the emit step is skipped.
static mut TX_REGISTERED: bool = false;
/// Local VA where eth_srv reads transmit payloads from.  Set by
/// try_register_eth_tx at startup.
static mut ETH_TX_LOCAL_VA: usize = 0;
/// Cached netif client id from the NETIF_REGISTER handshake.  Passed
/// back on every NETIF_XMIT.
static mut ETH_TX_CLIENT_ID: u64 = 0;
/// Cached eth_srv port for fast NETIF_XMIT dispatch.
static mut ETH_PORT: u64 = 0;
/// Resolved gateway MAC (packed 6 bytes into low 48 bits of u64).
/// Zero if NETIF_RESOLVE hasn't completed; we fall back to broadcast
/// in that case.
static mut GATEWAY_MAC: u64 = 0;
/// Egress capability bundle: the rights set we attach to flows
/// translated by this NAT engine.  Default attenuates CAP_LOCAL_ONLY
/// from CAP_DEFAULT — translated flows are by definition no longer
/// local-only, since they've been rewritten to a public address.
/// Surfaced in NAT_STATS.  CAP_DEFAULT + CAP_FORWARD bits without
/// CAP_LOCAL_ONLY: 0b0000_0000_1111 = INVOKE | READ | WRITE | FORWARD
/// (FORWARD added because the flow's already crossing a forwarding
/// hop and downstream consumers may legitimately re-forward).
const NAT_EGRESS_BUNDLE: u64 = 0x0000_000F;

/// Find a flow by (proto, private_ip, private_port).  Returns the
/// table index on hit.
fn flow_lookup_outbound(proto: u8, src_ip: u32, src_port: u16) -> Option<usize> {
    unsafe {
        for i in 0..FLOW_TABLE_SIZE {
            let f = &FLOW_TABLE[i];
            if f.in_use && f.proto == proto
                && f.private_ip == src_ip && f.private_port == src_port
            {
                return Some(i);
            }
        }
    }
    None
}

/// Find a flow by (proto, public_port).  Inbound reply lookup.
fn flow_lookup_inbound(proto: u8, public_port: u16) -> Option<usize> {
    unsafe {
        for i in 0..FLOW_TABLE_SIZE {
            let f = &FLOW_TABLE[i];
            if f.in_use && f.proto == proto && f.public_port == public_port {
                return Some(i);
            }
        }
    }
    None
}

/// Allocate a fresh flow entry; assigns a new public port from the
/// ephemeral pool.  Returns (slot, public_port).  Currently a simple
/// linear-scan + bump allocator; in production we'd recycle on
/// long-idle expiry.
fn flow_allocate(proto: u8, src_ip: u32, src_port: u16) -> Option<(usize, u16)> {
    unsafe {
        // Pick an unused slot.
        let mut slot: Option<usize> = None;
        for i in 0..FLOW_TABLE_SIZE {
            if !FLOW_TABLE[i].in_use {
                slot = Some(i);
                break;
            }
        }
        let slot = slot?;
        // Pick an unused public port — bump the counter, wrap on
        // PUBLIC_PORT_END, avoid colliding with other live flows.
        let mut tries = 0usize;
        let mut chosen: Option<u16> = None;
        loop {
            let p = NEXT_PUBLIC_PORT;
            NEXT_PUBLIC_PORT = if NEXT_PUBLIC_PORT >= PUBLIC_PORT_END {
                PUBLIC_PORT_BASE
            } else {
                NEXT_PUBLIC_PORT + 1
            };
            if flow_lookup_inbound(proto, p).is_none() {
                chosen = Some(p);
                break;
            }
            tries += 1;
            if tries > (PUBLIC_PORT_END - PUBLIC_PORT_BASE) as usize {
                return None; // pool exhausted
            }
        }
        let public_port = chosen?;
        FLOW_TABLE[slot] = FlowEntry {
            in_use: true,
            proto,
            private_ip: src_ip,
            private_port: src_port,
            public_port,
        };
        Some((slot, public_port))
    }
}

// ---------------------------------------------------------------------------
// IPv4 + TCP/UDP packet rewrite.  Big-endian wire format throughout.
// ---------------------------------------------------------------------------

fn read_u16_be(buf: &[u8], offset: usize) -> u16 {
    ((buf[offset] as u16) << 8) | (buf[offset + 1] as u16)
}

fn write_u16_be(buf: &mut [u8], offset: usize, v: u16) {
    buf[offset] = (v >> 8) as u8;
    buf[offset + 1] = (v & 0xFF) as u8;
}

fn read_u32_be(buf: &[u8], offset: usize) -> u32 {
    ((buf[offset] as u32) << 24)
        | ((buf[offset + 1] as u32) << 16)
        | ((buf[offset + 2] as u32) << 8)
        | (buf[offset + 3] as u32)
}

fn write_u32_be(buf: &mut [u8], offset: usize, v: u32) {
    buf[offset] = (v >> 24) as u8;
    buf[offset + 1] = (v >> 16) as u8;
    buf[offset + 2] = (v >> 8) as u8;
    buf[offset + 3] = v as u8;
}

/// Standard internet checksum (RFC 1071) over an arbitrary byte slice.
fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Result of header decoding.
struct Ipv4Decoded {
    /// Byte offset of the start of L4 (TCP/UDP) header.
    l4_offset: usize,
    /// IPv4 total length.
    total_len: usize,
    /// IPv4 protocol field.
    proto: u8,
    /// IPv4 source address (host order).
    src_ip: u32,
    /// IPv4 destination address (host order).
    dst_ip: u32,
    /// L4 source / destination ports.  Valid for TCP / UDP only.
    src_port: u16,
    dst_port: u16,
}

fn decode_ipv4(buf: &[u8]) -> Result<Ipv4Decoded, u64> {
    if buf.len() < 20 {
        return Err(ERR_PACKET_TOO_SHORT);
    }
    let version = buf[0] >> 4;
    if version != 4 {
        return Err(ERR_NOT_IPV4);
    }
    let ihl = (buf[0] & 0x0F) as usize * 4;
    if ihl < 20 || buf.len() < ihl {
        return Err(ERR_PACKET_TOO_SHORT);
    }
    let total_len = read_u16_be(buf, 2) as usize;
    if total_len > buf.len() || total_len < ihl {
        return Err(ERR_PACKET_TOO_SHORT);
    }
    let proto = buf[9];
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Err(ERR_UNSUPPORTED_PROTO);
    }
    let src_ip = read_u32_be(buf, 12);
    let dst_ip = read_u32_be(buf, 16);
    if total_len - ihl < 4 {
        return Err(ERR_PACKET_TOO_SHORT);
    }
    let src_port = read_u16_be(buf, ihl);
    let dst_port = read_u16_be(buf, ihl + 2);
    Ok(Ipv4Decoded {
        l4_offset: ihl,
        total_len,
        proto,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    })
}

/// Recompute IPv4 header checksum in place.  IHL is read from the
/// header byte 0.  Header checksum field is at offset 10..12.
fn recompute_ipv4_checksum(buf: &mut [u8]) {
    let ihl = (buf[0] & 0x0F) as usize * 4;
    write_u16_be(buf, 10, 0);
    let cksum = inet_checksum(&buf[..ihl]);
    write_u16_be(buf, 10, cksum);
}

/// Recompute TCP / UDP checksum in place using the IPv4 pseudo-header.
/// `l4_offset` is the start of the L4 header within `buf`; the L4
/// payload runs to total_len.  TCP checksum field is at l4_offset+16,
/// UDP checksum field at l4_offset+6.
fn recompute_l4_checksum(buf: &mut [u8], l4_offset: usize, total_len: usize, proto: u8) {
    let l4_len = total_len - l4_offset;
    let cksum_offset = match proto {
        IPPROTO_TCP => l4_offset + 16,
        IPPROTO_UDP => l4_offset + 6,
        _ => return,
    };
    // Zero the checksum field before computing.
    write_u16_be(buf, cksum_offset, 0);
    // Pseudo-header: src_ip (4) + dst_ip (4) + zero (1) + proto (1) +
    // l4_length (2).  All big-endian.
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&buf[12..16]); // src
    pseudo[4..8].copy_from_slice(&buf[16..20]); // dst
    pseudo[8] = 0;
    pseudo[9] = proto;
    pseudo[10] = (l4_len >> 8) as u8;
    pseudo[11] = (l4_len & 0xFF) as u8;
    // Checksum spans pseudo-header + L4 header + payload.
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < pseudo.len() {
        sum += ((pseudo[i] as u32) << 8) | (pseudo[i + 1] as u32);
        i += 2;
    }
    let mut j = l4_offset;
    while j + 1 < total_len {
        sum += ((buf[j] as u32) << 8) | (buf[j + 1] as u32);
        j += 2;
    }
    if j < total_len {
        sum += (buf[j] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let mut cksum = !(sum as u16);
    // UDP convention: 0 means "no checksum"; flip to 0xFFFF if computed
    // value is 0.
    if proto == IPPROTO_UDP && cksum == 0 {
        cksum = 0xFFFF;
    }
    write_u16_be(buf, cksum_offset, cksum);
}

/// Outbound rewrite: replace src_ip / src_port with our public IPv4
/// + an allocated public port.  Updates flow table.  On reply, data[1]
/// holds the allocated public port so the caller can correlate.
fn translate_out(buf: &mut [u8], len: usize) -> Result<(usize, u16), u64> {
    let decoded = decode_ipv4(&buf[..len])?;
    let public_ip = unsafe { PUBLIC_IPV4 };
    if public_ip == 0 {
        return Err(ERR_NOT_CONFIGURED);
    }

    // Look up or allocate flow entry.
    let public_port = match flow_lookup_outbound(decoded.proto, decoded.src_ip, decoded.src_port) {
        Some(idx) => unsafe { FLOW_TABLE[idx].public_port },
        None => {
            let (_idx, port) = flow_allocate(decoded.proto, decoded.src_ip, decoded.src_port)
                .ok_or(ERR_FLOW_TABLE_FULL)?;
            port
        }
    };

    // Rewrite src_ip + src_port.
    write_u32_be(buf, 12, public_ip);
    write_u16_be(buf, decoded.l4_offset, public_port);
    // Recompute checksums.
    recompute_l4_checksum(buf, decoded.l4_offset, decoded.total_len, decoded.proto);
    recompute_ipv4_checksum(&mut buf[..]);
    unsafe { TRANSLATED_OUT_COUNT += 1; }
    Ok((decoded.total_len, public_port))
}

/// Inbound rewrite: dst_ip / dst_port were our public IPv4 + a
/// previously-allocated public port; rewrite back to the original
/// (private_ip, private_port) recorded in the flow table.
fn translate_in(buf: &mut [u8], len: usize) -> Result<usize, u64> {
    let decoded = decode_ipv4(&buf[..len])?;
    let public_ip = unsafe { PUBLIC_IPV4 };
    if public_ip == 0 {
        return Err(ERR_NOT_CONFIGURED);
    }
    if decoded.dst_ip != public_ip {
        // Not destined for our public IP — caller shouldn't have sent
        // this our way; treat as no-flow.
        unsafe { DROPPED_COUNT += 1; }
        return Err(ERR_NO_FLOW);
    }
    let idx = flow_lookup_inbound(decoded.proto, decoded.dst_port)
        .ok_or_else(|| {
            unsafe { DROPPED_COUNT += 1; }
            ERR_NO_FLOW
        })?;
    let (priv_ip, priv_port) = unsafe {
        (FLOW_TABLE[idx].private_ip, FLOW_TABLE[idx].private_port)
    };
    write_u32_be(buf, 16, priv_ip);
    write_u16_be(buf, decoded.l4_offset + 2, priv_port);
    recompute_l4_checksum(buf, decoded.l4_offset, decoded.total_len, decoded.proto);
    recompute_ipv4_checksum(&mut buf[..]);
    unsafe { TRANSLATED_IN_COUNT += 1; }
    Ok(decoded.total_len)
}

/// Subscribe to non-local IPv4 frames via eth_srv's ETH_SUBSCRIBE.
/// Best-effort: if eth_srv isn't registered yet or the handshake fails,
/// we just skip and continue serving the explicit caller-driven path.
/// Sets `SUBSCRIBED=true` on success; the bool surfaces in NAT_STATS.
fn try_subscribe_to_eth(my_port: u64) {
    let eth_port = match syscall::ns_lookup(b"eth") {
        Some(p) => p,
        None => {
            syscall::debug_puts(b"  [nat_srv] eth not registered; auto-translate disabled\n");
            return;
        }
    };
    // Allocate a local RX page and grant it to eth_srv at the VA
    // eth_srv reports back in ETH_SUBSCRIBE_OK.
    let local_rx = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [nat_srv] mmap_anon for eth rx failed\n");
            return;
        }
    };
    // Pre-fault so the kernel grants a unique writable phys page to
    // eth_srv rather than the shared zero page.
    unsafe { core::ptr::write_volatile(local_rx as *mut u8, 0u8); }

    // Send ETH_SUBSCRIBE.  Filter = ethertype 0x0800 + FILTER_FLAG_NON_LOCAL.
    let filter_word = (ETHERTYPE_IPV4 as u64)
        | ((FILTER_FLAG_NON_LOCAL as u64) << 16);
    let _ = syscall::send_nb_4(
        eth_port,
        ETH_SUBSCRIBE,
        filter_word,
        0, // dst_ipv4 = 0, prefix_len = 0 (match any IPv4 dst)
        my_port,
        0,
    );
    // Wait for ETH_SUBSCRIBE_OK on our service port.  Bumped to 10s
    // because under pair-boot conditions eth_srv's IPC queue can be
    // backlogged behind NETIF_XMIT/handle_rx_packet work — observed
    // 2s timeout firing while the subscribe message was still pending
    // in eth_srv's queue (instance B Phase 5k, 2026-05-10).  10s gives
    // headroom; the proper architectural fix is to make eth_srv
    // drain IPC before poll_rx so control-plane messages don't queue
    // behind data-plane traffic.
    let resp = syscall::recv_msg_timeout(my_port, 10_000_000);
    let (_sub_id, eth_rx_va) = match resp {
        Some(m) if m.tag == ETH_SUBSCRIBE_OK => (m.data[0], m.data[1] as usize),
        _ => {
            syscall::debug_puts(b"  [nat_srv] ETH_SUBSCRIBE handshake failed\n");
            return;
        }
    };
    // Grant our local page to eth_srv at the reported VA.  After this,
    // eth_srv's writes to its rx_va appear at our local_rx.
    if !syscall::grant_pages(eth_port, local_rx, eth_rx_va, 1, false) {
        syscall::debug_puts(b"  [nat_srv] grant_pages to eth failed\n");
        return;
    }
    // Re-map ETH_RX_VA so subsequent ETH_FRAME handlers can read at a
    // known address regardless of mmap_anon's chosen va.  We just alias
    // local_rx as ETH_RX_VA via a const we agreed on earlier — the
    // ETH_FRAME handler reads from ETH_RX_VA, so that needs to equal
    // local_rx.  Simplest: store local_rx in a static and read from
    // there in the dispatch.
    unsafe { ETH_RX_LOCAL_VA = local_rx; SUBSCRIBED = true; }
    syscall::debug_puts(b"  [nat_srv] subscribed to non-local IPv4 frames\n");
}

/// Where ETH_SUBSCRIBE's grant lands in our aspace (set by
/// try_subscribe_to_eth at startup; 0 means not subscribed).
static mut ETH_RX_LOCAL_VA: usize = 0;

/// Register with eth_srv via NETIF_REGISTER to obtain a tx_grant_va
/// and client_id.  We use a placeholder ethertype (0xFFFE) so we
/// don't displace tcp4_srv's IPv4 ownership for RX dispatch — RX to
/// us flows through ETH_SUBSCRIBE, this registration is purely for
/// the egress side.  Best-effort: failures log and continue, leaving
/// observation-mode translation (no emit) as the fallback.
fn try_register_eth_tx(my_port: u64) {
    let eth_port = match syscall::ns_lookup(b"eth") {
        Some(p) => p,
        None => return,
    };
    unsafe { ETH_PORT = eth_port; }
    let local_tx = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [nat_srv] mmap_anon for eth tx failed\n");
            return;
        }
    };
    // Pre-fault.
    unsafe { core::ptr::write_volatile(local_tx as *mut u8, 0u8); }

    // Send NETIF_REGISTER on a fresh reply port to avoid colliding
    // with ETH_FRAME notifications on our service port.
    let reply_port = syscall::port_create();
    if reply_port == u64::MAX {
        syscall::debug_puts(b"  [nat_srv] port_create for tx reply failed\n");
        return;
    }
    let _ = syscall::send_nb_4(
        eth_port,
        NETIF_REGISTER,
        NETIF_XMIT_PLACEHOLDER_ETHERTYPE as u64,
        my_port, // eth_srv would use this for NETIF_INPUT — never fires
        reply_port,
        0,
    );
    let resp = syscall::recv_msg_timeout(reply_port, 2_000_000);
    let (cid, _eth_rx_va, eth_tx_va) = match resp {
        Some(m) if m.tag == NETIF_REGISTER_OK => {
            (m.data[0], m.data[1] as usize, m.data[2] as usize)
        }
        _ => {
            syscall::debug_puts(b"  [nat_srv] NETIF_REGISTER handshake failed\n");
            return;
        }
    };
    if !syscall::grant_pages(eth_port, local_tx, eth_tx_va, 1, false) {
        syscall::debug_puts(b"  [nat_srv] grant_pages tx -> eth failed\n");
        return;
    }
    unsafe {
        ETH_TX_LOCAL_VA = local_tx;
        ETH_TX_CLIENT_ID = cid;
        TX_REGISTERED = true;
    }
    syscall::debug_puts(b"  [nat_srv] egress (NETIF_XMIT) ready\n");
}

/// Resolve the gateway MAC via NETIF_RESOLVE.  Best-effort: caches
/// the result in GATEWAY_MAC for subsequent emits; on failure leaves
/// GATEWAY_MAC at 0 so emit_translated falls back to broadcast.
/// Called once at startup after the eth_srv handshakes complete.
fn try_resolve_gateway() {
    let eth_port = unsafe { ETH_PORT };
    if eth_port == 0 {
        return;
    }
    let reply_port = syscall::port_create();
    if reply_port == u64::MAX {
        return;
    }
    let _ = syscall::send_nb_4(
        eth_port,
        NETIF_RESOLVE,
        GATEWAY_IPV4 as u64,
        reply_port,
        0, 0,
    );
    // ARP can take a moment if the gateway hasn't been seen yet.
    // Give it a generous window — 1 s is plenty for a populated
    // ARP cache, and far less than typical ARP timeout for a fresh
    // resolution.
    let resp = syscall::recv_msg_timeout(reply_port, 1_000_000);
    match resp {
        Some(m) if m.tag == NETIF_RESOLVE_OK => {
            unsafe { GATEWAY_MAC = m.data[0]; }
            syscall::debug_puts(b"  [nat_srv] gateway MAC resolved\n");
        }
        _ => {
            syscall::debug_puts(b"  [nat_srv] gateway MAC unresolved (will broadcast)\n");
        }
    }
}

/// Emit a translated IPv4 packet via eth_srv's NETIF_XMIT path.
/// `ip_packet` is the IP packet bytes (no Ethernet header — eth_srv
/// builds the header from dst_mac + ethertype).  Uses the resolved
/// gateway MAC if available (from try_resolve_gateway), or falls
/// back to broadcast (dst_mac=0) if resolution failed.  Returns true
/// on emit success.
fn emit_translated(ip_packet: &[u8]) -> bool {
    unsafe {
        if !TX_REGISTERED || ETH_TX_LOCAL_VA == 0 {
            return false;
        }
        if ip_packet.len() > NAT_MAX_PACKET {
            return false;
        }
        // Copy into the granted TX page (which eth_srv reads from).
        core::ptr::copy_nonoverlapping(
            ip_packet.as_ptr(),
            ETH_TX_LOCAL_VA as *mut u8,
            ip_packet.len(),
        );
        // NETIF_XMIT data layout (matches eth_srv):
        //   data[0] = payload_len
        //   data[1] = dst_mac (0 = broadcast; non-zero = resolved MAC)
        //   data[2] = ethertype (low 16) | reply_port (high 32) — we
        //             don't bother with the reply.
        //   data[3] = client_id
        let dst_mac = GATEWAY_MAC; // 0 falls through to broadcast in eth_srv
        let _ = syscall::send_nb_4(
            ETH_PORT,
            NETIF_XMIT,
            ip_packet.len() as u64,
            dst_mac,
            ETHERTYPE_IPV4 as u64,
            ETH_TX_CLIENT_ID,
        );
    }
    true
}

/// Process one frame delivered via ETH_FRAME.  Increments counters
/// and runs translate_out on the inner IPv4 packet.  Doesn't re-emit
/// (NETIF_XMIT integration is a separate piece) — this is the
/// "observation-mode NAT" stage where we verify the dispatch path
/// works end-to-end before adding the egress side.
fn handle_eth_frame(frame_len: usize) {
    unsafe { SUBSCRIBED_FRAMES_COUNT += 1; }
    let rx_va = unsafe { ETH_RX_LOCAL_VA };
    if rx_va == 0 || frame_len < ETH_HDR_LEN + 20 || frame_len > NAT_MAX_PACKET {
        unsafe { SUBSCRIBED_DROPPED_COUNT += 1; }
        return;
    }
    let ip_len = frame_len - ETH_HDR_LEN;
    let ip_buf = unsafe {
        core::slice::from_raw_parts_mut(
            (rx_va + ETH_HDR_LEN) as *mut u8,
            ip_len,
        )
    };
    match translate_out(ip_buf, ip_len) {
        Ok((new_len, _public_port)) => {
            unsafe { SUBSCRIBED_TRANSLATED_COUNT += 1; }
            // Emit the translated packet via NETIF_XMIT.  Best-effort:
            // egress may not be ready (TX_REGISTERED=false) on the
            // first frames; subsequent frames will succeed once the
            // handshake catches up.  In observation mode (no TX
            // registration) this becomes a no-op and the frame is
            // simply translated-but-not-emitted.
            let emit_buf = unsafe {
                core::slice::from_raw_parts(
                    (rx_va + ETH_HDR_LEN) as *const u8,
                    new_len,
                )
            };
            if emit_translated(emit_buf) {
                unsafe { SUBSCRIBED_EMITTED_COUNT += 1; }
            }
        }
        Err(_) => unsafe { SUBSCRIBED_DROPPED_COUNT += 1; },
    }
}

// ---------------------------------------------------------------------------
// Server entry point.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
fn main(_a0: u64, _a1: u64, _a2: u64) {
    syscall::debug_puts(b"[nat_srv] starting (NAT44 source-NAT live; NAT64 still stub)\n");

    let port = syscall::port_create();
    if port == u64::MAX {
        syscall::debug_puts(b"[nat_srv] port_create FAIL\n");
        syscall::exit(1);
    }
    // Default the public IPv4 to RFC 5737's 192.0.2.1 so the
    // translate_out engine has a non-zero public address even before
    // a caller invokes NAT_SET_PUBLIC_IPV4 explicitly.
    unsafe { PUBLIC_IPV4 = DEFAULT_PUBLIC_IPV4; }

    // Auto-subscribe to non-local IPv4 frames via eth_srv's
    // ETH_SUBSCRIBE.  This is the first end-to-end use of the
    // forwarding-plane substrate composing two real services: the
    // dispatch (Piece a, eth_srv) feeds frames into the NAT engine
    // without explicit caller orchestration.  Best-effort — failures
    // log and continue; the explicit caller-driven NAT_TRANSLATE_*
    // path stays available regardless.
    //
    // CRITICAL: try_subscribe_to_eth's recv_msg_timeout consumes
    // ANY message at `port`, not just ETH_SUBSCRIBE_OK.  If
    // ns_register("nat") happens before this call, init's
    // ns_lookup_wait("nat") returns immediately and a follow-up
    // syscall::call (e.g. NAT_STATS in Phase 5k) lands on `port`
    // before subscribe runs — and gets eaten silently by the
    // recv_msg_timeout below, with no reply, leading to a
    // CALL_REPLY_SERVER_DIED watchdog reply ("FAILED (bad reply)").
    // Subscribe + register + resolve must complete BEFORE we publish
    // the port via ns_register.
    try_subscribe_to_eth(port);

    // Register with eth_srv for NETIF_XMIT egress.  This closes the
    // NAT loop end-to-end: subscribe -> translate -> emit.  Uses a
    // placeholder ethertype (0xFFFE) so we don't displace tcp4_srv's
    // ownership of 0x0800 for RX.
    try_register_eth_tx(port);

    // Resolve the gateway MAC so emit_translated targets the real
    // next hop instead of broadcasting.  Best-effort; on failure
    // emit_translated falls back to dst_mac=0 (broadcast).
    try_resolve_gateway();

    // Publish the service port now that bring-up is complete.  Any
    // messages that arrive after this land in the main-loop's
    // recv_with_cap (which installs reply caps correctly).
    if !syscall::ns_register(b"nat", port) {
        syscall::debug_puts(b"[nat_srv] ns_register FAIL\n");
        syscall::exit(1);
    }

    syscall::debug_puts(b"[nat_srv] ready on port ");
    print_num(port);
    syscall::debug_puts(b"\n");

    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => continue,
        };
        match msg.tag {
            NAT_SET_PUBLIC_IPV4 => {
                unsafe { PUBLIC_IPV4 = msg.data[0] as u32; }
                let _ = syscall::reply(NAT_SET_PUBLIC_IPV4_OK, 0, 0, 0, 0, 0);
            }
            NAT_TRANSLATE_OUT => {
                let len = msg.data[0] as usize;
                if len == 0 || len > NAT_MAX_PACKET {
                    let _ = syscall::reply(NAT_ERR, ERR_PACKET_TOO_SHORT, 0, 0, 0, 0);
                    continue;
                }
                let buf = unsafe {
                    core::slice::from_raw_parts_mut(NAT_SCRATCH_VA as *mut u8, len)
                };
                match translate_out(buf, len) {
                    Ok((new_len, public_port)) => {
                        let _ = syscall::reply(
                            NAT_TRANSLATE_OUT_OK,
                            new_len as u64,
                            public_port as u64,
                            0,
                            0,
                            0,
                        );
                    }
                    Err(e) => {
                        let _ = syscall::reply(NAT_ERR, e, 0, 0, 0, 0);
                    }
                }
            }
            NAT_TRANSLATE_IN => {
                let len = msg.data[0] as usize;
                if len == 0 || len > NAT_MAX_PACKET {
                    let _ = syscall::reply(NAT_ERR, ERR_PACKET_TOO_SHORT, 0, 0, 0, 0);
                    continue;
                }
                let buf = unsafe {
                    core::slice::from_raw_parts_mut(NAT_SCRATCH_VA as *mut u8, len)
                };
                match translate_in(buf, len) {
                    Ok(new_len) => {
                        let _ = syscall::reply(
                            NAT_TRANSLATE_IN_OK,
                            new_len as u64,
                            0,
                            0,
                            0,
                            0,
                        );
                    }
                    Err(e) => {
                        let _ = syscall::reply(NAT_ERR, e, 0, 0, 0, 0);
                    }
                }
            }
            NAT_STATS => {
                let occupancy = {
                    let mut n = 0u64;
                    unsafe {
                        for i in 0..FLOW_TABLE_SIZE {
                            if FLOW_TABLE[i].in_use { n += 1; }
                        }
                    }
                    n
                };
                unsafe {
                    // Pack substrate state + attenuation into the upper
                    // bits of the flow-occupancy reply word so the
                    // existing explicit translate counters still occupy
                    // data[1..3].  Layout:
                    //   data[0] = flow occupancy (low 32) |
                    //             SUBSCRIBED (bit 32) |
                    //             TX_REGISTERED (bit 33) |
                    //             GATEWAY_MAC_RESOLVED (bit 34) |
                    //             NAT_EGRESS_BUNDLE (bits 35..43) |
                    //             subscribed_frames (bits 44..63).
                    //   data[1] = TRANSLATED_OUT_COUNT
                    //   data[2] = TRANSLATED_IN_COUNT
                    //   data[3] = DROPPED_COUNT (caller-driven path)
                    //   data[4] = SUBSCRIBED_TRANSLATED |
                    //             (SUBSCRIBED_EMITTED << 24) |
                    //             (SUBSCRIBED_DROPPED << 48)
                    let gateway_resolved = (GATEWAY_MAC != 0) as u64;
                    let bundle_field = NAT_EGRESS_BUNDLE & 0x1FF; // 9 bits
                    let stat_a = occupancy
                        | ((SUBSCRIBED as u64) << 32)
                        | ((TX_REGISTERED as u64) << 33)
                        | (gateway_resolved << 34)
                        | (bundle_field << 35)
                        | ((SUBSCRIBED_FRAMES_COUNT & 0x000F_FFFF) << 44);
                    let stat_e = (SUBSCRIBED_TRANSLATED_COUNT & 0xFFFFFF)
                        | ((SUBSCRIBED_EMITTED_COUNT & 0xFFFFFF) << 24)
                        | ((SUBSCRIBED_DROPPED_COUNT & 0xFFFF) << 48);
                    let _ = syscall::reply(
                        NAT_STATS_OK,
                        stat_a,
                        TRANSLATED_OUT_COUNT,
                        TRANSLATED_IN_COUNT,
                        DROPPED_COUNT,
                        stat_e,
                    );
                }
            }
            ETH_FRAME => {
                // Forwarding-plane frame from eth_srv subscription.
                // No reply expected (sender used send_nb_4).
                let frame_len = msg.data[0] as usize;
                handle_eth_frame(frame_len);
            }
            // Late-arriving handshake replies on our main service port.
            // try_subscribe_to_eth and try_register_eth_tx use this port
            // as their reply target; if the round-trip exceeds the
            // bringup timeout the *_OK message can still land here after
            // the main loop is running.  No cap, no reply expected — but
            // we MUST handle them explicitly: the catch-all `_` arm
            // below replies with NAT_ERR, which would re-use the held
            // cap from a *different* in-flight call (e.g. init's
            // NAT_STATS) and surface as "FAILED (bad reply)" upstream.
            ETH_SUBSCRIBE_OK
            | NETIF_REGISTER_OK => {
                // Silently consume — nothing to do.  These succeeded
                // late; the bringup path already gave up and proceeded
                // best-effort, so we can't flip the SUBSCRIBED /
                // TX_REGISTERED bits without re-running the grant
                // setup.  Matters more that we DON'T misuse the cap
                // by falling through to the catch-all NAT_ERR reply
                // below.
            }
            NAT_SET_NAT64_PREFIX
            | NAT_TRANSLATE_V6_TO_V4
            | NAT_TRANSLATE_V4_TO_V6
            | NAT_PORTFORWARD_ADD
            | NAT_PORTFORWARD_DEL => {
                // NAT64 + portforwarding still stubs.
                let _ = syscall::reply(NAT_ERR, ERR_NOT_IMPLEMENTED, 0, 0, 0, 0);
            }
            _ => {
                let _ = syscall::reply(NAT_ERR, ERR_NOT_IMPLEMENTED, 0, 0, 0, 0);
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
