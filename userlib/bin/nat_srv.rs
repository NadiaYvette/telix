//! nat_srv — NAT (network address translation) scaffold.
//!
//! Reserves the spot for IPv4 / IPv6 dual-stack interop.  The user's
//! flagged interest is specifically the IPv4 / IPv6 compatibility
//! story: many real-world deployments are IPv6-only (mobile carriers,
//! ISPs that ran out of IPv4, container hosts) but need to reach
//! IPv4-only services on the wider internet.  NAT64 / NAT46 (per
//! RFC 6146 + RFC 6877 + RFC 7269) is the canonical answer.
//!
//! Coverage the eventual implementation needs:
//!   - **NAT44** (classic IPv4-to-IPv4, source-NAT for outbound +
//!     destination-NAT for inbound port-forwards).  The simplest case;
//!     a port-mapping table keyed by (proto, src_ip, src_port,
//!     dst_ip, dst_port).
//!   - **NAT66** (IPv6-to-IPv6 prefix translation per RFC 6296).
//!     Mostly stateless; rewrites the prefix portion of v6 addresses
//!     between two networks.
//!   - **NAT64 stateful** (RFC 6146).  The IPv6-only host sends to a
//!     IPv6 address in a well-known prefix (`64:ff9b::/96`); the
//!     NAT translator rewrites that to an IPv4 destination by
//!     extracting the v4 address from the low 32 bits of the v6
//!     destination, allocating a v4 source port, and bookkeeping
//!     the translation so reply packets get rewritten back.
//!   - **NAT46 / DNS64** for completeness — the IPv6-only host needs
//!     a DNS resolver that synthesises AAAA records pointing into the
//!     well-known prefix when only A records exist.  DNS64 lives in
//!     the resolver, not here, but the two systems coordinate via the
//!     prefix configuration.
//!   - **ICMP rewrite.** ICMP echo/error messages need their inner
//!     header rewritten too, otherwise traceroute / Path MTU
//!     discovery break.
//!   - **Stateful flow tracking** with per-flow timeout, capacity
//!     limits, and graceful eviction.  Eventually integrates with
//!     the security-policy server.
//!
//! Service name: registered as b"nat" so the IP stack
//! (`ip6_srv` / `tcp4_srv` / `net_srv`) can lift packets out of
//! direct routing and through translation when configured to.

#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

// ---------------------------------------------------------------------------
// Message protocol (placeholder).
// ---------------------------------------------------------------------------

/// Configure the NAT64 well-known prefix (default 64:ff9b::/96 per
/// RFC 6052).  data[0..4] = 16-byte prefix bytes (4 u64 words).
/// data[4 high] = prefix length in bits.
pub const NAT_SET_NAT64_PREFIX: u64 = 0x7C01;
pub const NAT_SET_NAT64_PREFIX_OK: u64 = 0x7C02;

/// Add an explicit static port-forward (NAT44 inbound).
/// data[0] = (proto << 24) | local_port, data[1] = backend ipv4 BE32,
/// data[2] = backend port.
pub const NAT_PORTFORWARD_ADD: u64 = 0x7C10;
pub const NAT_PORTFORWARD_ADD_OK: u64 = 0x7C11;
pub const NAT_PORTFORWARD_DEL: u64 = 0x7C12;
pub const NAT_PORTFORWARD_DEL_OK: u64 = 0x7C13;

/// Translate an outbound IPv6 packet whose destination falls in the
/// configured NAT64 prefix.  Returns the IPv4 packet to forward, plus
/// allocates a state-table entry so the matching reply gets translated
/// back.  data[0] = ingress packet grant_va, data[1] = packet length;
/// reply data[0] = egress packet grant_va, data[1] = egress length.
pub const NAT_TRANSLATE_V6_TO_V4: u64 = 0x7C20;
pub const NAT_TRANSLATE_V6_TO_V4_OK: u64 = 0x7C21;
/// Inbound IPv4 reply → IPv6.  Looks up the state-table entry created
/// by the matching NAT_TRANSLATE_V6_TO_V4 and reverses.
pub const NAT_TRANSLATE_V4_TO_V6: u64 = 0x7C22;
pub const NAT_TRANSLATE_V4_TO_V6_OK: u64 = 0x7C23;

/// NAT44 source-NAT for outbound IPv4 traffic — picks a public source
/// port from the pool, records the mapping, returns the rewritten
/// header values to the caller.
pub const NAT_SOURCE_NAT_V4: u64 = 0x7C30;
pub const NAT_SOURCE_NAT_V4_OK: u64 = 0x7C31;

/// Statistics: pool occupancy, oldest entry age, eviction count.
/// Useful for the WATCHDOG dump and for capacity planning.
pub const NAT_STATS: u64 = 0x7C40;
pub const NAT_STATS_OK: u64 = 0x7C41;

/// Generic error (out-of-scope, not implemented, table full, ...).
pub const NAT_ERR: u64 = 0x7CFF;
pub const ERR_NOT_IMPLEMENTED: u64 = 1;

#[unsafe(no_mangle)]
fn main(_a0: u64, _a1: u64, _a2: u64) {
    syscall::debug_puts(b"[nat_srv] starting (scaffold - no real translation yet)\n");

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
        // Scaffold: every protocol op acks with NOT_IMPLEMENTED.
        // Real flow tables / rewrite logic drop into the match arms.
        let (rep_tag, rep_d0) = match msg.tag {
            NAT_SET_NAT64_PREFIX => (NAT_ERR, ERR_NOT_IMPLEMENTED),
            NAT_PORTFORWARD_ADD => (NAT_ERR, ERR_NOT_IMPLEMENTED),
            NAT_PORTFORWARD_DEL => (NAT_ERR, ERR_NOT_IMPLEMENTED),
            NAT_TRANSLATE_V6_TO_V4 => (NAT_ERR, ERR_NOT_IMPLEMENTED),
            NAT_TRANSLATE_V4_TO_V6 => (NAT_ERR, ERR_NOT_IMPLEMENTED),
            NAT_SOURCE_NAT_V4 => (NAT_ERR, ERR_NOT_IMPLEMENTED),
            NAT_STATS => (NAT_ERR, ERR_NOT_IMPLEMENTED),
            _ => (NAT_ERR, ERR_NOT_IMPLEMENTED),
        };
        let _ = syscall::reply(rep_tag, rep_d0, 0, 0, 0, 0);
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
