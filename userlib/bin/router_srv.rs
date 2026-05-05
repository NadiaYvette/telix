//! router_srv — forwarding-plane consumer + ETH_SUBSCRIBE validator.
//!
//! Subscribes to non-local IPv4 frames via eth_srv's ETH_SUBSCRIBE
//! protocol (Piece (a) of the distributed-strategy design).  Today
//! it just counts frames and prints stats — the architectural slot
//! is the same one nat_srv (translation), proxy_srv (forward to a
//! bonded remote), discovery (multicast capture) all hook into; this
//! binary is the canonical consumer that lets us verify the
//! subscription surface end-to-end.
//!
//! Lifecycle:
//!   1. ns_lookup("eth") to get eth_srv's port.
//!   2. mmap_anon(1 page) for the local RX buffer.
//!   3. Send ETH_SUBSCRIBE with filter = (ethertype 0x0800 IPv4,
//!      flags = FILTER_FLAG_NON_LOCAL).
//!   4. Receive ETH_SUBSCRIBE_OK, learn sub_id + eth's expected
//!      rx_grant_va.
//!   5. grant_pages from local rx_va into eth's rx_grant_va.
//!   6. Loop on recv for ~1 second, counting ETH_FRAME notifications.
//!   7. Send ETH_UNSUBSCRIBE.
//!   8. Print PASS/FAIL + frame count.
//!
//! Pass criterion: subscribe + grant + unsubscribe round-trip
//! succeeds.  Frame count is informational — depending on what's
//! flowing on the virtual network during the test window, it may
//! be zero (e.g., no ARP / ICMP traffic during a quiet boot).
//!
//! Wire-up: spawned as Phase 5j right after the servicereg test.

#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

// ETH_SUBSCRIBE protocol (matches eth_srv).
const ETH_SUBSCRIBE: u64 = 0x5500;
const ETH_SUBSCRIBE_OK: u64 = 0x5501;
const ETH_UNSUBSCRIBE: u64 = 0x5510;
const ETH_UNSUBSCRIBE_OK: u64 = 0x5511;
const ETH_FRAME: u64 = 0x5520;

const ETHERTYPE_IPV4: u16 = 0x0800;
const FILTER_FLAG_NON_LOCAL: u64 = 1 << 0;

fn report(label: &[u8], pass: bool) -> bool {
    syscall::debug_puts(if pass { b"  [router_srv] PASS " } else { b"  [router_srv] FAIL " });
    syscall::debug_puts(label);
    syscall::debug_puts(b"\n");
    pass
}

#[unsafe(no_mangle)]
fn main(_a0: u64, _a1: u64, _a2: u64) {
    syscall::debug_puts(b"[router_srv] starting\n");

    // Wait for eth_srv to be ready.
    let mut wait = 0u32;
    let eth_port = loop {
        if let Some(p) = syscall::ns_lookup(b"eth") {
            break p;
        }
        if wait >= 500 {
            let _ = report(b"eth_srv never registered", false);
            syscall::exit(1);
        }
        syscall::sleep_ms(10);
        wait += 1;
    };

    // Allocate local RX page.  eth_srv copies frame bytes here once
    // we establish the grant; one frame at a time.
    let local_rx_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            let _ = report(b"mmap_anon for rx page", false);
            syscall::exit(1);
        }
    };

    // Subscribe.  We use a dedicated reply port for the SUBSCRIBE_OK
    // and for ETH_FRAME notifications — same port handles both
    // since they're distinguishable by tag.
    let my_port = syscall::port_create();
    if my_port == u64::MAX {
        let _ = report(b"port_create", false);
        syscall::exit(1);
    }

    // ETH_SUBSCRIBE encoding (matches eth_srv):
    //   data[0] = ethertype filter (low 16) | flags (next 8)
    //   data[1] = IPv4 dst (low 32) | prefix_len (next 8)
    //   data[2] = reply_port
    let filter_word =
        (ETHERTYPE_IPV4 as u64)
        | ((FILTER_FLAG_NON_LOCAL as u64) << 16);
    syscall::send_nb_4(
        eth_port,
        ETH_SUBSCRIBE,
        filter_word,
        0, // dst_ipv4 = 0, prefix_len = 0 (match any IPv4 dst)
        my_port,
        0,
    );

    // Wait for SUBSCRIBE_OK.
    let (sub_id, eth_rx_va) = match syscall::recv_msg_timeout(my_port, 2_000_000) {
        Some(msg) if msg.tag == ETH_SUBSCRIBE_OK => {
            let sid = msg.data[0];
            let va = msg.data[1] as usize;
            (sid, va)
        }
        Some(_) => {
            let _ = report(b"unexpected reply to ETH_SUBSCRIBE", false);
            syscall::exit(1);
        }
        None => {
            let _ = report(b"ETH_SUBSCRIBE timed out", false);
            syscall::exit(1);
        }
    };
    let _ = report(b"ETH_SUBSCRIBE returned OK", true);

    // Grant our local RX page to eth_srv at the reported VA.  After
    // this, eth_srv's writes to eth_rx_va are visible at our local_rx_va.
    let granted = syscall::grant_pages(eth_port, local_rx_va, eth_rx_va, 1, false);
    let _ = report(b"grant_pages local rx -> eth", granted);
    if !granted {
        let _ = syscall::send_nb_4(eth_port, ETH_UNSUBSCRIBE, sub_id, my_port, 0, 0);
        syscall::exit(1);
    }

    // Receive loop: ~1 second budget.  Count ETH_FRAME notifications.
    // Frame bytes sit in local_rx_va; for the validator we don't
    // bother decoding them, just confirm the dispatch fires.
    let mut frame_count: u64 = 0;
    let start_ms = monotonic_ms();
    while monotonic_ms() - start_ms < 1000 {
        match syscall::recv_msg_timeout(my_port, 100_000) {
            Some(msg) if msg.tag == ETH_FRAME => {
                frame_count += 1;
            }
            Some(_) => {
                // Unexpected tag — count separately?  For now ignore.
            }
            None => {
                // Timeout — keep polling until total budget elapses.
            }
        }
    }

    syscall::debug_puts(b"  [router_srv] observed ");
    print_num(frame_count);
    syscall::debug_puts(b" non-local IPv4 frame(s) in 1s window\n");

    // Unsubscribe.
    let unsub_reply = syscall::port_create();
    syscall::send_nb_4(eth_port, ETH_UNSUBSCRIBE, sub_id, unsub_reply, 0, 0);
    let unsub_ok = matches!(
        syscall::recv_msg_timeout(unsub_reply, 1_000_000),
        Some(m) if m.tag == ETH_UNSUBSCRIBE_OK
    );
    let _ = report(b"ETH_UNSUBSCRIBE round-trip", unsub_ok);

    if unsub_ok {
        syscall::debug_puts(b"[router_srv] PASSED (subscribe/grant/unsubscribe)\n");
        syscall::exit(0);
    } else {
        syscall::debug_puts(b"[router_srv] FAILED\n");
        syscall::exit(1);
    }
}

fn monotonic_ms() -> u64 {
    syscall::clock_gettime() / 1_000_000
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
