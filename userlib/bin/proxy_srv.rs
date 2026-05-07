#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;
use userlib::syscall::Message;

// --- Proxy protocol constants ---

/// Marker in low 32 bits of tag for proxy-redirected messages.
const PROXY_MARKER_LO: u64 = 0xFFFF_0001;

/// Admin IPC: add a node mapping.
/// data[0] = node_id, data[1] = ip_be32, data[2] = tcp_port | (reply_port << 32)
const PROXY_ADD_NODE: u64 = 0x5000;
const PROXY_ADD_NODE_OK: u64 = 0x5001;

/// Send a frame to a peer over the Ethernet-direct transport.
///
/// Caller pre-grants a page in our aspace containing the message
/// *body* — exactly:
///   bytes  0..16: dst_service_uuid
///   bytes 16..32: src_service_uuid
///   bytes 32..40: request_id (LE u64; 0 if not needed for matching)
///   bytes 40..N:  payload
/// proxy_srv prepends the 8-byte wire header (magic + version +
/// reserved + len) and ships via NETIF_XMIT.  Body length is bounded
/// by MTU - 8 ≈ 1492 bytes (40-byte routing header + ≤ 1452 payload).
///
/// in:  data[0] = peer MAC (mac_to_u64 encoding; resolved from
///                SVCREG_LOOKUP_REMOTE_OK)
///      data[1] = grant_va in our aspace where the body lives
///      data[2] = body_len (>= 40 for the routing header to be valid)
///
/// Reply: PROXY_SEND_BY_PEER_OK on success; PROXY_SEND_BY_PEER_FAIL
/// if the Ethernet transport hasn't completed its eth_srv handshake
/// yet, or body_len is too small / too large.
///
/// Transport selection is per-call for now (this RPC means "use
/// Ethernet"); a future trait-based dispatcher will pick TCP vs.
/// Ethernet based on per-node config.
const PROXY_SEND_BY_PEER: u64 = 0x5010;
const PROXY_SEND_BY_PEER_OK: u64 = 0x5011;
const PROXY_SEND_BY_PEER_FAIL: u64 = 0x501F;

/// Routing header prefix size (dst_uuid + src_uuid + request_id) at the
/// start of every proxy frame body.
const ROUTING_HDR_LEN: usize = 16 + 16 + 8;

/// Subscribe a port to receive demuxed inbound proxy frames whose
/// dst_service_uuid matches a specified UUID.  proxy_srv maintains a
/// linear table of (uuid, port) pairs; on each inbound frame, the
/// dst_service_uuid is looked up and forwarded to that subscriber.
///
/// in:  data[0..2] = service UUID (LE-packed two u64 words)
///      data[2]    = subscriber port
///      data[3]    = inbound_grant_va — caller pre-grants a page in
///                   their aspace at this VA where proxy_srv writes
///                   each delivered frame body (UUIDs + payload).
///                   Notification (PROXY_INBOUND_FRAME) carries the
///                   length; subscriber reads bytes from grant_va.
const PROXY_SUBSCRIBE_INBOUND: u64 = 0x5020;
const PROXY_SUBSCRIBE_INBOUND_OK: u64 = 0x5021;
/// Notification fired to a subscriber's port when a matching frame
/// arrives.  data[0] = body_len (header + payload that got written
/// to the subscriber's grant_va).  data[1] = src_mac of the sender.
const PROXY_INBOUND_FRAME: u64 = 0x5022;

/// Test-only inject path, mirroring discovery_srv's
/// DISCOVERY_INJECT_FRAME.  Lets a single-instance test exercise the
/// receive path without needing eth_srv loopback (which QEMU user-mode
/// networking doesn't provide).  Caller grants a page at data[0],
/// sends payload_len in data[1], synthetic src_mac in data[2].
const PROXY_INJECT_FRAME: u64 = 0x5030;
const PROXY_INJECT_FRAME_OK: u64 = 0x5031;

// Eth_srv NETIF protocol — must match userlib/bin/eth_srv.rs.  Inlined
// here so this binary doesn't take a userlib dependency on eth_srv's
// header constants.  Note: NETIF_REGISTER's wire value (0x5000) is the
// same as PROXY_ADD_NODE's, but they're disambiguated by destination
// port — proxy_srv sends NETIF_REGISTER to eth_srv's port, and
// receives PROXY_ADD_NODE on its own.
const ETH_NETIF_REGISTER: u64 = 0x5000;
const ETH_NETIF_REGISTER_OK: u64 = 0x5001;
const ETH_NETIF_INPUT: u64 = 0x5100;
const ETH_NETIF_XMIT: u64 = 0x5200;

/// Ethertype reserved for Telix proxy (cross-device IPC) frames.
/// Adjacent to discovery_srv's 0xD15C so the two distributed-bonding
/// channels are easy to identify in packet captures.
const ETHERTYPE_PROXY: u64 = 0xD15D;

// --- Net_srv IPC tags ---
const NET_TCP_CONNECT: u64 = 0x4200;
const NET_TCP_CONNECTED: u64 = 0x4201;
const NET_TCP_FAIL: u64 = 0x42FF;
const NET_TCP_SEND: u64 = 0x4300;
const NET_TCP_SEND_OK: u64 = 0x4301;
const NET_TCP_RECV_NB: u64 = 0x4410;
const NET_TCP_DATA: u64 = 0x4401;
const NET_TCP_RECV_NONE: u64 = 0x4412;
const NET_TCP_BIND: u64 = 0x4600;
const NET_TCP_BIND_OK: u64 = 0x4601;
const NET_TCP_LISTEN: u64 = 0x4700;
const NET_TCP_LISTEN_OK: u64 = 0x4701;
const NET_TCP_ACCEPT: u64 = 0x4710;
const NET_TCP_ACCEPT_OK: u64 = 0x4711;
const NET_TCP_CLOSED: u64 = 0x44FF;

// --- Wire protocol ---
const WIRE_MAGIC: u32 = 0x544C5850; // "TLXP"
const WIRE_FRAME_SIZE: usize = 64;

// --- Capability bundle bits (mirror userlib::services::CAP_*) ---
// Kept inline here so the wire frame can attenuate without a userlib
// dependency cycle.  Must match userlib/src/services.rs.
const CAP_READ: u64 = 1 << 0;
const CAP_WRITE: u64 = 1 << 1;
const CAP_INVOKE: u64 = 1 << 2;
const CAP_LOCAL_ONLY: u64 = 1 << 8;
/// Default outbound bundle when the caller doesn't supply one.  Same
/// shape as userlib::services::CAP_DEFAULT (INVOKE | READ | WRITE |
/// LOCAL_ONLY); LOCAL_ONLY gets attenuated below before leaving the
/// node.
const PROXY_DEFAULT_BUNDLE: u64 = CAP_INVOKE | CAP_READ | CAP_WRITE | CAP_LOCAL_ONLY;
/// Mask applied on the egress path: drop CAP_LOCAL_ONLY because by the
/// time a frame leaves this node over TCP it has, by definition, left
/// the local addressing domain.  Other bits (READ/WRITE/INVOKE/FORWARD/
/// CONFIDENTIAL/INTEGRITY/etc.) propagate unchanged so the receiver
/// sees the rights set the registrant declared, minus locality.
const PROXY_EGRESS_ATTENUATION: u64 = !CAP_LOCAL_ONLY;

// --- Limits ---
const MAX_NODES: usize = 16;
const LISTEN_TCP_PORT: u16 = 9100;

const NONE_CONN: usize = usize::MAX;

// --- Node table entry ---
struct NodeEntry {
    active: bool,
    node_id: u16,
    ip_be32: u32,
    tcp_port: u16,
    conn_id: usize,
    // Receive accumulator for incoming frames.
    rx_buf: [u8; WIRE_FRAME_SIZE],
    rx_len: usize,
    // Pending connect: true if we sent NET_TCP_CONNECT but haven't got reply yet.
    connecting: bool,
}

impl NodeEntry {
    const fn empty() -> Self {
        Self {
            active: false,
            node_id: 0,
            ip_be32: 0,
            tcp_port: 0,
            conn_id: NONE_CONN,
            rx_buf: [0; WIRE_FRAME_SIZE],
            rx_len: 0,
            connecting: false,
        }
    }
}

struct ProxySrv {
    my_port: u64,
    reply_port: u64,
    net_port: u64,
    my_node_id: u16,
    nodes: [NodeEntry; MAX_NODES],
    // Pending accept: true if we're waiting for incoming connections.
    accepting: bool,
}

// ---------------------------------------------------------------------------
// Transport abstraction.
//
// proxy_srv supports multiple transports (today: Ethernet-direct;
// near-term follow-ups: TCP under this same trait, eventually TLS/
// BLE-PAN).  PeerAddr is the union of address types each transport
// expects; Transport is the dispatch enum the main loop calls into.
// Per-call selection today comes from the IPC tag (PROXY_SEND_BY_PEER
// implies "use Ethernet").  Future per-node config will let
// SVCREG_LOOKUP_REMOTE pick the right transport for each peer.
//
// Worklist (next commits):
// - Migrate existing TCP code (handle_outbound/handle_inbound_data/
//   handle_accept) into Transport::Tcp variant
// - Reassembly when body > MTU
// - Pre-shared-key auth as a transport-agnostic middleware
// ---------------------------------------------------------------------------

#[allow(dead_code)] // Tcp4 variant is staged for the next commit
enum PeerAddr {
    /// L2 Ethernet address (mac_to_u64 encoding).  Resolved from
    /// SVCREG_LOOKUP_REMOTE_OK.data[3].
    Ethernet { mac: u64 },
    /// IPv4+TCP — used by the existing TCP transport once it migrates
    /// under the trait.  Currently the TCP path doesn't go through
    /// Transport so this variant is unconstructed.
    Tcp4 { ip: u32, port: u16 },
}

/// Ethernet transport state — what was a flock of static muts before
/// the trait refactor, now owned by a single struct so multiple
/// instances (e.g. for testing, or for separate ethertypes) can be
/// instantiated independently.
struct EthernetTransport {
    eth_port: u64,
    tx_local_va: usize,
    rx_local_va: usize,
    tx_client_id: u64,
    registered: bool,
}

impl EthernetTransport {
    const fn new() -> Self {
        Self {
            eth_port: 0,
            tx_local_va: 0,
            rx_local_va: 0,
            tx_client_id: 0,
            registered: false,
        }
    }

    fn ready(&self) -> bool {
        self.registered
    }

    fn rx_local_va(&self) -> usize {
        self.rx_local_va
    }
}

/// Dispatch enum.  Add variants for new transports; the main loop
/// uses `Transport::send`, `Transport::ready`, and (for inbound)
/// `Transport::rx_local_va`.
#[allow(dead_code)] // Tcp variant is staged for the next commit
enum Transport {
    Ethernet(EthernetTransport),
    /// TODO: migrate existing handle_outbound/handle_inbound_data/
    /// handle_accept into a TcpTransport that constructs into this
    /// variant.  Tracked as next clustering worklist item.
    Tcp,
}

impl Transport {
    /// Send a fully-formed proxy body (40-byte routing header +
    /// payload) to the peer.  Returns true on successful submission.
    fn send(&self, peer: &PeerAddr, body: &[u8]) -> bool {
        match self {
            Transport::Ethernet(eth) => match peer {
                PeerAddr::Ethernet { mac } => eth_send_to_peer(eth, *mac, body),
                _ => false, // wrong peer addr type for this transport
            },
            Transport::Tcp => false, // not yet under the trait
        }
    }

    fn ready(&self) -> bool {
        match self {
            Transport::Ethernet(e) => e.ready(),
            Transport::Tcp => false,
        }
    }

    /// Returns the local VA where inbound frames land for this
    /// transport, or 0 if the transport isn't ready / has no inbound
    /// path.
    fn rx_local_va(&self) -> usize {
        match self {
            Transport::Ethernet(e) => e.rx_local_va(),
            Transport::Tcp => 0,
        }
    }
}

/// Single global transport handle.  Future revisions may have
/// multiple (one per network or transport class) and dispatch by
/// per-node config; for now there's exactly one Ethernet transport.
static mut TRANSPORT: Transport = Transport::Ethernet(EthernetTransport::new());
/// Per-UUID subscriber registration.
#[derive(Copy, Clone)]
struct InboundSubscriber {
    in_use: bool,
    uuid: [u8; 16],
    port: u64,
    /// Caller-supplied VA where we write each delivered frame body.
    /// In the caller's aspace (granted to us at sub time).
    grant_va: usize,
}

const MAX_INBOUND_SUBSCRIBERS: usize = 16;
static mut INBOUND_SUBSCRIBERS: [InboundSubscriber; MAX_INBOUND_SUBSCRIBERS] = [
    InboundSubscriber { in_use: false, uuid: [0; 16], port: 0, grant_va: 0 };
    MAX_INBOUND_SUBSCRIBERS
];

static mut INBOUND_FRAMES_RECEIVED: u64 = 0;
static mut INBOUND_FRAMES_REJECTED: u64 = 0;
static mut INBOUND_FRAMES_NO_SUB: u64 = 0;

/// Best-effort registration with eth_srv for ETHERTYPE_PROXY on the TX
/// side.  Same shape as discovery_srv::try_register_eth_tx — alloc an
/// anon page, pre-fault it, NETIF_REGISTER, grant the page in.  Also
/// allocates an RX page so eth_srv can deliver inbound proxy frames.
fn try_register_eth_proxy(eth: &mut EthernetTransport, my_port: u64) {
    let eth_port = match syscall::ns_lookup(b"eth") {
        Some(p) => p,
        None => {
            syscall::debug_puts(
                b"  [proxy_srv] eth not registered; ethernet xmit disabled\n",
            );
            return;
        }
    };
    eth.eth_port = eth_port;
    let local_tx = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [proxy_srv] mmap_anon for eth tx failed\n");
            return;
        }
    };
    let local_rx = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [proxy_srv] mmap_anon for eth rx failed\n");
            return;
        }
    };
    unsafe {
        core::ptr::write_volatile(local_tx as *mut u8, 0u8);
        core::ptr::write_volatile(local_rx as *mut u8, 0u8);
    }

    let reply_port = syscall::port_create();
    if reply_port == u64::MAX {
        syscall::debug_puts(b"  [proxy_srv] port_create for eth tx reply failed\n");
        return;
    }
    let _ = syscall::send_nb_4(
        eth_port,
        ETH_NETIF_REGISTER,
        ETHERTYPE_PROXY,
        my_port,
        reply_port,
        0,
    );
    let resp = syscall::recv_msg_timeout(reply_port, 2_000_000);
    let (cid, eth_rx_va, eth_tx_va) = match resp {
        Some(m) if m.tag == ETH_NETIF_REGISTER_OK => {
            (m.data[0], m.data[1] as usize, m.data[2] as usize)
        }
        _ => {
            syscall::debug_puts(b"  [proxy_srv] eth NETIF_REGISTER handshake failed\n");
            return;
        }
    };
    if !syscall::grant_pages(eth_port, local_tx, eth_tx_va, 1, false) {
        syscall::debug_puts(b"  [proxy_srv] grant_pages eth tx failed\n");
        return;
    }
    if !syscall::grant_pages(eth_port, local_rx, eth_rx_va, 1, false) {
        syscall::debug_puts(b"  [proxy_srv] grant_pages eth rx failed\n");
        return;
    }
    eth.tx_local_va = local_tx;
    eth.rx_local_va = local_rx;
    eth.tx_client_id = cid;
    eth.registered = true;
    syscall::debug_puts(
        b"  [proxy_srv] ethernet xmit+rx registered (peer-routed transport ready)\n",
    );
}

/// Parse an inbound proxy frame at `buf_va` (in our aspace) and, if
/// valid, demux to the subscriber registered for the dst_service_uuid.
/// Shared by the real receive path (handle_eth_inbound) and the
/// test-only inject path (PROXY_INJECT_FRAME) so they can't drift on
/// header layout / magic / UUID layout.
fn parse_proxy_frame_from(buf_va: usize, frame_len: usize, src_mac: u64) {
    unsafe {
        INBOUND_FRAMES_RECEIVED += 1;
        // Need 8-byte wire header + 40-byte routing header at minimum.
        if buf_va == 0 || frame_len < 8 + ROUTING_HDR_LEN {
            INBOUND_FRAMES_REJECTED += 1;
            return;
        }
        let buf = buf_va as *const u8;
        // Validate magic (first 4 bytes).
        let mut mag_bytes = [0u8; 4];
        for i in 0..4 { mag_bytes[i] = core::ptr::read_volatile(buf.add(i)); }
        if u32::from_le_bytes(mag_bytes) != WIRE_MAGIC {
            INBOUND_FRAMES_REJECTED += 1;
            return;
        }
        let version = core::ptr::read_volatile(buf.add(4));
        if version != 1 {
            INBOUND_FRAMES_REJECTED += 1;
            return;
        }
        let len_lo = core::ptr::read_volatile(buf.add(6));
        let len_hi = core::ptr::read_volatile(buf.add(7));
        let body_len = (len_lo as usize) | ((len_hi as usize) << 8);
        if 8 + body_len > frame_len || body_len < ROUTING_HDR_LEN {
            INBOUND_FRAMES_REJECTED += 1;
            return;
        }
        // Read dst_service_uuid from body bytes 0..16.
        let body_va = buf.add(8);
        let mut dst_uuid = [0u8; 16];
        for i in 0..16 { dst_uuid[i] = core::ptr::read_volatile(body_va.add(i)); }
        // Look up subscriber.
        let mut sub_idx: Option<usize> = None;
        for i in 0..MAX_INBOUND_SUBSCRIBERS {
            if INBOUND_SUBSCRIBERS[i].in_use && INBOUND_SUBSCRIBERS[i].uuid == dst_uuid {
                sub_idx = Some(i);
                break;
            }
        }
        let idx = match sub_idx {
            Some(i) => i,
            None => {
                INBOUND_FRAMES_NO_SUB += 1;
                return; // no demux target; drop silently (counted)
            }
        };
        let sub = &INBOUND_SUBSCRIBERS[idx];
        // Copy body bytes (the routing header + payload) into the
        // subscriber's grant_va.  Single contiguous write — subscriber
        // reads back from their granted VA.
        let dst = sub.grant_va as *mut u8;
        for i in 0..body_len {
            core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(body_va.add(i)));
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        let _ = syscall::send_nb_4(
            sub.port,
            PROXY_INBOUND_FRAME,
            body_len as u64,
            src_mac,
            0, 0,
        );
    }
}

/// Handle a NETIF_INPUT notification from eth_srv.  data[0] =
/// payload_len, data[1] = src_mac.  Shared parser keeps the real and
/// inject paths consistent.
fn handle_eth_inbound(payload_len: usize, src_mac: u64) {
    let rx_va = unsafe {
        match &*(&raw const TRANSPORT) {
            Transport::Ethernet(e) => e.rx_local_va(),
            _ => 0,
        }
    };
    if rx_va == 0 {
        unsafe {
            INBOUND_FRAMES_RECEIVED += 1;
            INBOUND_FRAMES_REJECTED += 1;
        }
        return;
    }
    parse_proxy_frame_from(rx_va, payload_len, src_mac);
}

/// Build a frame at the transport's tx_local_va from a fully-formed
/// body (must already include the 40-byte routing header: dst_uuid +
/// src_uuid + request_id, followed by payload) and send it via
/// NETIF_XMIT to the given peer MAC.  Returns true on success.
/// body length is bounded by MTU - 8 ≈ 1492 bytes.
fn eth_send_to_peer(eth: &EthernetTransport, peer_mac: u64, body: &[u8]) -> bool {
    if !eth.registered || eth.tx_local_va == 0 || eth.eth_port == 0 {
        return false;
    }
    if body.len() < ROUTING_HDR_LEN {
        return false;
    }
    unsafe {
        let dst = eth.tx_local_va as *mut u8;
        let mag = WIRE_MAGIC.to_le_bytes();
        for i in 0..4 { core::ptr::write_volatile(dst.add(i), mag[i]); }
        core::ptr::write_volatile(dst.add(4), 1u8); // version
        core::ptr::write_volatile(dst.add(5), 0u8); // reserved
        let len_le = (body.len() as u16).to_le_bytes();
        core::ptr::write_volatile(dst.add(6), len_le[0]);
        core::ptr::write_volatile(dst.add(7), len_le[1]);
        for i in 0..body.len() {
            core::ptr::write_volatile(dst.add(8 + i), body[i]);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("mfence");

        let frame_len = 8 + body.len();
        let _ = syscall::send_nb_4(
            eth.eth_port,
            ETH_NETIF_XMIT,
            frame_len as u64,
            peer_mac,
            ETHERTYPE_PROXY,
            eth.tx_client_id,
        );
    }
    true
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

// --- Wire frame serialization ---

fn serialize_frame(
    buf: &mut [u8; WIRE_FRAME_SIZE],
    target_port: u64,
    tag: u64,
    data: &[u64; 4],
    src_node: u16,
    bundle: u64,
) {
    // Bytes 0-3: magic
    buf[0..4].copy_from_slice(&WIRE_MAGIC.to_le_bytes());
    // Bytes 4-7: target_port (with node=0 for local delivery on remote side)
    let local_port = (target_port & 0xFFFF) as u32; // strip node, deliver locally on remote
    buf[4..8].copy_from_slice(&local_port.to_le_bytes());
    // Bytes 8-15: tag
    buf[8..16].copy_from_slice(&tag.to_le_bytes());
    // Bytes 16-47: data[0..3]
    for i in 0..4 {
        let off = 16 + i * 8;
        buf[off..off + 8].copy_from_slice(&data[i].to_le_bytes());
    }
    // Bytes 48-49: source node ID
    buf[48..50].copy_from_slice(&src_node.to_le_bytes());
    // Bytes 50-57: capability bundle (attenuated for egress — see
    // PROXY_EGRESS_ATTENUATION; CAP_LOCAL_ONLY is dropped because the
    // frame is leaving this node).
    let attenuated = bundle & PROXY_EGRESS_ATTENUATION;
    buf[50..58].copy_from_slice(&attenuated.to_le_bytes());
    // Bytes 58-63: padding (reserved for future protocol extensions —
    // candidates: integrity MAC, sequence number, flow-id).
    buf[58..64].fill(0);
}

fn deserialize_frame(buf: &[u8; WIRE_FRAME_SIZE]) -> Option<(u64, u64, [u64; 4], u16, u64)> {
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != WIRE_MAGIC {
        return None;
    }
    let target_port = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
    let tag = u64::from_le_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
    let mut data = [0u64; 4];
    for i in 0..4 {
        let off = 16 + i * 8;
        data[i] = u64::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
            buf[off + 4],
            buf[off + 5],
            buf[off + 6],
            buf[off + 7],
        ]);
    }
    let src_node = u16::from_le_bytes([buf[48], buf[49]]);
    let bundle = u64::from_le_bytes([
        buf[50], buf[51], buf[52], buf[53], buf[54], buf[55], buf[56], buf[57],
    ]);
    Some((target_port, tag, data, src_node, bundle))
}

// --- TCP helpers ---

/// Pack up to 16 bytes into two u64 words for inline NET_TCP_SEND.
fn pack16(data: &[u8]) -> (u64, u64) {
    let mut w0: u64 = 0;
    let mut w1: u64 = 0;
    for i in 0..data.len().min(8) {
        w0 |= (data[i] as u64) << (i * 8);
    }
    for i in 0..data.len().saturating_sub(8).min(8) {
        w1 |= (data[8 + i] as u64) << (i * 8);
    }
    (w0, w1)
}

/// Unpack up to 24 bytes from 3 u64 data words (NET_TCP_DATA format).
fn unpack24(d1: u64, d2: u64, d3: u64, out: &mut [u8], len: usize) {
    let n = len.min(24);
    for i in 0..n.min(8) {
        out[i] = (d1 >> (i * 8)) as u8;
    }
    for i in 0..n.saturating_sub(8).min(8) {
        out[8 + i] = (d2 >> (i * 8)) as u8;
    }
    for i in 0..n.saturating_sub(16).min(8) {
        out[16 + i] = (d3 >> (i * 8)) as u8;
    }
}

impl ProxySrv {
    fn find_node_by_id(&self, node_id: u16) -> Option<usize> {
        self.nodes
            .iter()
            .position(|n| n.active && n.node_id == node_id)
    }

    fn find_node_by_conn(&self, conn_id: usize) -> Option<usize> {
        self.nodes
            .iter()
            .position(|n| n.active && n.conn_id == conn_id)
    }

    /// Send a 64-byte wire frame as 4 × 16-byte TCP sends.
    fn tcp_send_frame(&self, conn_id: usize, frame: &[u8; WIRE_FRAME_SIZE]) {
        for chunk_idx in 0..4 {
            let off = chunk_idx * 16;
            let (w0, w1) = pack16(&frame[off..off + 16]);
            let d1 = (16u64) | ((self.reply_port as u64) << 16);
            syscall::send(self.net_port, NET_TCP_SEND, conn_id as u64, d1, w0, w1);
            // Wait for send_ok (consume reply).
            loop {
                if let Some(reply) = syscall::recv_msg(self.reply_port) {
                    if reply.tag == NET_TCP_SEND_OK
                        || reply.tag == NET_TCP_FAIL
                        || reply.tag == NET_TCP_CLOSED
                    {
                        break;
                    }
                    // Unexpected message on reply port — might be from accept/connect.
                    self.handle_reply(reply);
                } else {
                    break;
                }
            }
        }
    }

    /// Initiate TCP connection to a node if not already connected.
    fn ensure_connection(&mut self, node_idx: usize) {
        if self.nodes[node_idx].conn_id != NONE_CONN || self.nodes[node_idx].connecting {
            return;
        }
        let ip = self.nodes[node_idx].ip_be32;
        let port = self.nodes[node_idx].tcp_port;
        let d1 = (port as u64) | ((self.reply_port) << 32);
        syscall::send(self.net_port, NET_TCP_CONNECT, ip as u64, d1, 0, 0);
        self.nodes[node_idx].connecting = true;

        // Block for connect reply.
        loop {
            if let Some(reply) = syscall::recv_msg(self.reply_port) {
                match reply.tag {
                    NET_TCP_CONNECTED => {
                        let cid = reply.data[0] as usize;
                        self.nodes[node_idx].conn_id = cid;
                        self.nodes[node_idx].connecting = false;
                        syscall::debug_puts(b"  [proxy] connected to node ");
                        print_num(self.nodes[node_idx].node_id as u64);
                        syscall::debug_puts(b" conn=");
                        print_num(cid as u64);
                        syscall::debug_puts(b"\n");
                        break;
                    }
                    NET_TCP_FAIL => {
                        self.nodes[node_idx].connecting = false;
                        syscall::debug_puts(b"  [proxy] connect failed\n");
                        break;
                    }
                    _ => {
                        self.handle_reply(reply);
                    }
                }
            } else {
                break;
            }
        }
    }

    /// Handle outbound proxy message (kernel-redirected non-local send).
    fn handle_outbound(&mut self, msg: &Message) {
        // New wire protocol: data[0] = target_port, data[1] = original_tag, data[2..4] = data[0..2]
        let target_port = msg.data[0];
        let node_id = (target_port >> 44) as u16; // 20|44 split: node in top 20 bits
        let original_tag = msg.data[1];
        let original_data = [msg.data[2], msg.data[3], msg.data[4], 0];

        let node_idx = match self.find_node_by_id(node_id) {
            Some(i) => i,
            None => {
                syscall::debug_puts(b"  [proxy] unknown node ");
                print_num(node_id as u64);
                syscall::debug_puts(b"\n");
                return;
            }
        };

        self.ensure_connection(node_idx);
        if self.nodes[node_idx].conn_id == NONE_CONN {
            return; // Connect failed.
        }

        let mut frame = [0u8; WIRE_FRAME_SIZE];
        // Cross-device send carries a capability bundle so the remote
        // recipient sees the rights set the originator declared.  We
        // don't yet have per-flow bundle plumbing back to the kernel
        // proxy redirect path (msg.data carries (target_port, tag,
        // data...) but no bundle slot today), so use the default
        // bundle here; serialize_frame attenuates LOCAL_ONLY before
        // the bytes hit the wire.  When proxy_register grows a
        // per-port bundle hint, this picks it up automatically.
        serialize_frame(
            &mut frame,
            target_port,
            original_tag,
            &original_data,
            self.my_node_id,
            PROXY_DEFAULT_BUNDLE,
        );
        self.tcp_send_frame(self.nodes[node_idx].conn_id, &frame);
    }

    /// Handle inbound TCP data — accumulate into frame buffer.
    fn handle_inbound_data(&mut self, conn_id: usize, data_len: usize, d1: u64, d2: u64, d3: u64) {
        let node_idx = match self.find_node_by_conn(conn_id) {
            Some(i) => i,
            None => return, // Unknown connection.
        };

        let entry = &mut self.nodes[node_idx];
        let space = WIRE_FRAME_SIZE - entry.rx_len;
        let n = data_len.min(space).min(24);
        let mut tmp = [0u8; 24];
        unpack24(d1, d2, d3, &mut tmp, n);
        entry.rx_buf[entry.rx_len..entry.rx_len + n].copy_from_slice(&tmp[..n]);
        entry.rx_len += n;

        // Process complete frames.
        while entry.rx_len >= WIRE_FRAME_SIZE {
            let frame: [u8; WIRE_FRAME_SIZE] = {
                let mut f = [0u8; WIRE_FRAME_SIZE];
                f.copy_from_slice(&entry.rx_buf[..WIRE_FRAME_SIZE]);
                f
            };
            // Shift remaining data.
            let remaining = entry.rx_len - WIRE_FRAME_SIZE;
            for i in 0..remaining {
                entry.rx_buf[i] = entry.rx_buf[WIRE_FRAME_SIZE + i];
            }
            entry.rx_len = remaining;

            if let Some((target_port, tag, data, _src_node, _bundle)) =
                deserialize_frame(&frame)
            {
                // Deliver locally.  The bundle the sender propagated
                // is dropped on the floor for now — the local IPC
                // shape (4 data words) has no slot to forward it
                // through.  When ports grow per-message bundle
                // metadata, the inbound bundle would attach here so
                // the local receiver sees the (already-attenuated)
                // cross-device rights set.
                syscall::send_nb_4(target_port, tag, data[0], data[1], data[2], data[3]);
            }
        }
    }

    /// Handle non-proxy reply messages that arrive on the reply port.
    fn handle_reply(&self, _msg: Message) {
        // Consume accept/connect/data replies we don't need right now.
    }

    /// Poll TCP connections for incoming data (non-blocking).
    fn poll_inbound(&mut self) {
        for i in 0..MAX_NODES {
            if !self.nodes[i].active || self.nodes[i].conn_id == NONE_CONN {
                continue;
            }
            let conn_id = self.nodes[i].conn_id;
            // NET_TCP_RECV_NB: data[0]=conn_id, data[1]=reply_port<<16
            let d1 = (self.reply_port as u64) << 16;
            syscall::send_nb(self.net_port, NET_TCP_RECV_NB, conn_id as u64, d1);
            // Check reply port for response.
            if let Some(reply) = syscall::recv_nb_msg(self.reply_port) {
                match reply.tag {
                    NET_TCP_DATA => {
                        let len = reply.data[0] as usize;
                        self.handle_inbound_data(
                            conn_id,
                            len,
                            reply.data[1],
                            reply.data[2],
                            reply.data[3],
                        );
                    }
                    NET_TCP_RECV_NONE => {} // No data.
                    NET_TCP_CLOSED => {
                        syscall::debug_puts(b"  [proxy] conn closed for node ");
                        print_num(self.nodes[i].node_id as u64);
                        syscall::debug_puts(b"\n");
                        self.nodes[i].conn_id = NONE_CONN;
                    }
                    _ => {}
                }
            }
        }
    }

    /// Handle admin: add node mapping.
    fn handle_add_node(&mut self, msg: &Message) {
        let node_id = msg.data[0] as u16;
        let ip_be32 = msg.data[1] as u32;
        let tcp_port = (msg.data[2] & 0xFFFF) as u16;
        let reply_port = msg.data[2] >> 32;

        // Find a free slot or existing entry for this node_id.
        let slot = self.find_node_by_id(node_id).unwrap_or_else(|| {
            self.nodes
                .iter()
                .position(|n| !n.active)
                .unwrap_or(MAX_NODES)
        });

        if slot < MAX_NODES {
            self.nodes[slot] = NodeEntry {
                active: true,
                node_id,
                ip_be32,
                tcp_port,
                conn_id: NONE_CONN,
                rx_buf: [0; WIRE_FRAME_SIZE],
                rx_len: 0,
                connecting: false,
            };
            syscall::debug_puts(b"  [proxy] added node ");
            print_num(node_id as u64);
            syscall::debug_puts(b"\n");
            if reply_port != 0 {
                syscall::send_nb(reply_port, PROXY_ADD_NODE_OK, node_id as u64, 0);
            }
        }
    }

    /// Issue a non-blocking accept on the listen port.
    fn try_accept(&mut self) {
        if self.accepting {
            return;
        }
        let d1 = ((self.reply_port as u64) << 32) | (LISTEN_TCP_PORT as u64);
        // NET_TCP_ACCEPT: data[0]=port, data[1] has reply_port in upper 32 bits.
        syscall::send_nb(self.net_port, NET_TCP_ACCEPT, LISTEN_TCP_PORT as u64, d1);
        self.accepting = true;
    }

    /// Handle accepted connection: assign to a node slot.
    fn handle_accept(&mut self, conn_id: usize) {
        self.accepting = false;
        // Find a free node slot for this incoming connection.
        // The remote will identify itself in the first wire frame's src_node field.
        // For now, assign a temporary node slot. We'll update once we get the first frame.
        for i in 0..MAX_NODES {
            if !self.nodes[i].active {
                self.nodes[i] = NodeEntry {
                    active: true,
                    node_id: 0xFFFF, // Unknown until first frame.
                    ip_be32: 0,
                    tcp_port: 0,
                    conn_id,
                    rx_buf: [0; WIRE_FRAME_SIZE],
                    rx_len: 0,
                    connecting: false,
                };
                syscall::debug_puts(b"  [proxy] accepted conn=");
                print_num(conn_id as u64);
                syscall::debug_puts(b"\n");
                break;
            }
        }
        // Re-issue accept for next connection.
        self.try_accept();
    }
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    let my_port = syscall::port_create();
    let reply_port = syscall::port_create();

    // Register as the kernel proxy endpoint.
    syscall::proxy_register(my_port);

    // Look up net_srv.
    let net_port = loop {
        if let Some(p) = syscall::ns_lookup(b"net") {
            break p;
        }
        syscall::yield_now();
    };

    // Register with name server.
    syscall::ns_register(b"proxy", my_port);

    syscall::debug_puts(b"  [proxy_srv] ready on port ");
    print_num(my_port);
    syscall::debug_puts(b"\n");

    // Bring up the parallel Ethernet-direct transport via the
    // Transport abstraction.  Best-effort — if eth_srv isn't up yet,
    // the transport stays !ready() and PROXY_SEND_BY_PEER returns
    // FAIL until eth_srv comes online.
    unsafe {
        if let Transport::Ethernet(eth) = &mut *(&raw mut TRANSPORT) {
            try_register_eth_proxy(eth, my_port);
        }
    }

    // Bind + listen on LISTEN_TCP_PORT for incoming proxy connections.
    let d1_bind = (LISTEN_TCP_PORT as u64) | ((reply_port) << 32);
    syscall::send(
        net_port,
        NET_TCP_BIND,
        LISTEN_TCP_PORT as u64,
        d1_bind,
        0,
        0,
    );
    // Wait for bind reply.
    if let Some(reply) = syscall::recv_msg(reply_port) {
        if reply.tag == NET_TCP_BIND_OK {
            let d2_listen = (reply_port << 32);
            syscall::send(
                net_port,
                NET_TCP_LISTEN,
                LISTEN_TCP_PORT as u64,
                1,
                d2_listen,
                0,
            );
            let _ = syscall::recv_msg(reply_port); // LISTEN_OK
        }
    }

    let mut srv = ProxySrv {
        my_port,
        reply_port,
        net_port,
        my_node_id: 0, // This node is node 0 by default.
        nodes: [const { NodeEntry::empty() }; MAX_NODES],
        accepting: false,
    };

    // Start accepting incoming connections.
    srv.try_accept();

    // Create port set for multiplexed recv.
    let set_id = syscall::port_set_create() as u32;
    syscall::port_set_add(set_id, my_port);
    syscall::port_set_add(set_id, reply_port);

    // Main loop: use port_set_recv with timeout for periodic polling.
    loop {
        // Try non-blocking port set recv first.
        if let Some((from_port, msg)) = syscall::port_set_recv(set_id) {
            if msg.tag == PROXY_MARKER_LO && from_port == my_port {
                // Outbound: kernel-redirected non-local send.
                srv.handle_outbound(&msg);
            } else if msg.tag == ETH_NETIF_INPUT {
                // eth_srv delivered an ETHERTYPE_PROXY frame.
                // data[0] = payload_len, data[1] = src_mac.
                handle_eth_inbound(msg.data[0] as usize, msg.data[1]);
            } else if msg.tag == PROXY_SUBSCRIBE_INBOUND {
                // data[0..2] = uuid (LE-packed), data[2] = port,
                // data[3] = grant_va (where to deliver bodies).
                let mut uuid = [0u8; 16];
                uuid[0..8].copy_from_slice(&msg.data[0].to_le_bytes());
                uuid[8..16].copy_from_slice(&msg.data[1].to_le_bytes());
                let port = msg.data[2];
                let grant_va = msg.data[3] as usize;
                let mut ok = false;
                unsafe {
                    // If this UUID is already subscribed, update the
                    // entry (re-subscription is allowed).  Otherwise
                    // find a free slot.
                    let mut slot: Option<usize> = None;
                    for i in 0..MAX_INBOUND_SUBSCRIBERS {
                        if INBOUND_SUBSCRIBERS[i].in_use && INBOUND_SUBSCRIBERS[i].uuid == uuid {
                            slot = Some(i);
                            break;
                        }
                    }
                    if slot.is_none() {
                        for i in 0..MAX_INBOUND_SUBSCRIBERS {
                            if !INBOUND_SUBSCRIBERS[i].in_use {
                                slot = Some(i);
                                break;
                            }
                        }
                    }
                    if let Some(i) = slot {
                        INBOUND_SUBSCRIBERS[i] = InboundSubscriber {
                            in_use: true, uuid, port, grant_va,
                        };
                        ok = true;
                    }
                }
                let tag = if ok { PROXY_SUBSCRIBE_INBOUND_OK } else { PROXY_SEND_BY_PEER_FAIL };
                let _ = syscall::reply(tag, 0, 0, 0, 0, 0);
            } else if msg.tag == PROXY_INJECT_FRAME {
                // Test-only path mirroring discovery_srv's
                // DISCOVERY_INJECT_FRAME.  Caller has granted a page
                // at data[0]; parse via the same code path as a real
                // NETIF_INPUT frame.
                let buf_va = msg.data[0] as usize;
                let payload_len = msg.data[1] as usize;
                let src_mac = msg.data[2];
                parse_proxy_frame_from(buf_va, payload_len, src_mac);
                let _ = syscall::reply(PROXY_INJECT_FRAME_OK, 0, 0, 0, 0, 0);
            } else if msg.tag == PROXY_SEND_BY_PEER {
                // Grant-based path: caller pre-granted a body page
                // at data[1] containing dst_uuid + src_uuid +
                // request_id + payload.  Reply OK / FAIL.  Dispatch
                // through the Transport abstraction so future TLS /
                // BLE-PAN transports plug in at the same call site.
                let mac = msg.data[0];
                let body_va = msg.data[1] as usize;
                let body_len = msg.data[2] as usize;
                let ok = if body_va == 0
                    || body_len < ROUTING_HDR_LEN
                    || body_len > 1492
                    || !syscall::va_writable(body_va)
                {
                    false
                } else {
                    let body = unsafe {
                        core::slice::from_raw_parts(body_va as *const u8, body_len)
                    };
                    let peer = PeerAddr::Ethernet { mac };
                    unsafe { (*(&raw const TRANSPORT)).send(&peer, body) }
                };
                let tag = if ok { PROXY_SEND_BY_PEER_OK } else { PROXY_SEND_BY_PEER_FAIL };
                let _ = syscall::reply(tag, 0, 0, 0, 0, 0);
            } else if msg.tag == PROXY_ADD_NODE {
                srv.handle_add_node(&msg);
            } else if msg.tag == NET_TCP_DATA && from_port == reply_port {
                // Inbound TCP data.
                let conn_id_guess = 0; // We need to figure out which conn this is for.
                // NET_TCP_DATA: data[0]=len, data[1..3]=bytes.
                // Unfortunately NET_TCP_DATA doesn't include conn_id in standard flow.
                // We'll use poll_inbound instead for receiving.
                let len = msg.data[0] as usize;
                // Try all active connections.
                for i in 0..MAX_NODES {
                    if srv.nodes[i].active && srv.nodes[i].conn_id != NONE_CONN {
                        srv.handle_inbound_data(
                            srv.nodes[i].conn_id,
                            len,
                            msg.data[1],
                            msg.data[2],
                            msg.data[3],
                        );
                        break;
                    }
                }
            } else if msg.tag == NET_TCP_ACCEPT_OK && from_port == reply_port {
                let conn_id = msg.data[0] as usize;
                srv.handle_accept(conn_id);
            } else if msg.tag == NET_TCP_CONNECTED && from_port == reply_port {
                // Connection established — handled in ensure_connection's blocking loop.
            } else if msg.tag == NET_TCP_RECV_NONE {
                // No data, ignore.
            }
        }

        // Poll inbound data on all connections periodically.
        srv.poll_inbound();
    }
}
