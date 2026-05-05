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
                    let _ = syscall::reply(
                        NAT_STATS_OK,
                        occupancy,
                        TRANSLATED_OUT_COUNT,
                        TRANSLATED_IN_COUNT,
                        DROPPED_COUNT,
                        0,
                    );
                }
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
