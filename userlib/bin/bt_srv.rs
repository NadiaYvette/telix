//! bt_srv — Bluetooth host stack scaffold.
//!
//! Reserves the architectural spot for Telix's Bluetooth implementation.
//! No real HCI traffic happens yet; the message-protocol skeleton is in
//! place so callers (a discovery service, a PAN driver, a HID input
//! shim, an audio sink) can wire up against it and the substantive HCI
//! transport / L2CAP / GATT work can fill in incrementally.
//!
//! The eventual implementation needs (per Tier 6 of the strategy doc):
//!   - HCI transport driver: USB Bluetooth class (most laptops) or
//!     UART (most embedded targets / Raspberry Pi).  This is the
//!     boundary where bytes actually go in and out of the radio
//!     hardware.
//!   - HCI command / event framework: parse HCI events, dispatch
//!     commands with completion routing.
//!   - L2CAP for LE-credit-based flow-controlled channels.
//!   - GAP (advertising, scanning, connection initiation) and GATT
//!     (attribute discovery + characteristic read/write).
//!   - SMP / pairing for authenticated bonded links.
//!   - PAN / BNEP / IPSP for IP-over-Bluetooth — important for
//!     seamless device-to-device data flow without Wi-Fi in the
//!     middle.
//!
//! Each layer above lands as a separate concern; this scaffold's job is
//! to give them somewhere to live.
//!
//! Service name: registered as b"bluetooth" in the nameserver so any
//! client (BLE-discovery-srv, PAN driver, etc.) can find it via
//! syscall::ns_lookup(b"bluetooth").

#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

// ---------------------------------------------------------------------------
// Message protocol (placeholder — wire-protocol versioning belongs here once
// real HCI traffic flows).  Tags are in the 0x7B00 range to avoid collision
// with existing servers.
// ---------------------------------------------------------------------------

/// Send a raw HCI command packet to the controller.
/// data[0] = opcode (OGF | OCF, packed),  data[1] = arg-length (low 16) +
/// the first 6 bytes of arg buffer in the upper bits.  Long arg buffers
/// will use a grant-based variant once the transport is real.
pub const BT_HCI_CMD: u64 = 0x7B01;
pub const BT_HCI_CMD_OK: u64 = 0x7B02;

/// Subscribe to HCI events.  data[0] = event-mask of interest
/// (LE_META, CONNECTION_COMPLETE, DISCONNECTION_COMPLETE, ...).
/// Future deliveries land on data[3] = caller's reply port.
pub const BT_HCI_EVT_SUBSCRIBE: u64 = 0x7B03;
pub const BT_HCI_EVT_SUBSCRIBE_OK: u64 = 0x7B04;

/// Begin LE advertising with default device-identity payload.
pub const BT_LE_ADV_START: u64 = 0x7B10;
pub const BT_LE_ADV_START_OK: u64 = 0x7B11;
/// Stop LE advertising.
pub const BT_LE_ADV_STOP: u64 = 0x7B12;
pub const BT_LE_ADV_STOP_OK: u64 = 0x7B13;

/// Begin LE scanning.  Subscribe via BT_HCI_EVT_SUBSCRIBE first to get
/// scan-result events.
pub const BT_LE_SCAN_START: u64 = 0x7B20;
pub const BT_LE_SCAN_START_OK: u64 = 0x7B21;
pub const BT_LE_SCAN_STOP: u64 = 0x7B22;
pub const BT_LE_SCAN_STOP_OK: u64 = 0x7B23;

/// PAN / BNEP / IPSP scaffolding: open an IP-over-BLE link to a peer.
/// Real implementation provides a netif-like bridge so the IP stack
/// (`ip6_srv` / `tcp4_srv`) can route packets through the BT link.
pub const BT_PAN_OPEN: u64 = 0x7B30;
pub const BT_PAN_OPEN_OK: u64 = 0x7B31;

/// Generic error (out-of-scope, not implemented, transport down, ...).
pub const BT_ERR: u64 = 0x7BFF;
pub const ERR_NOT_IMPLEMENTED: u64 = 1;

#[unsafe(no_mangle)]
fn main(_a0: u64, _a1: u64, _a2: u64) {
    syscall::debug_puts(b"[bt_srv] starting (scaffold - no real HCI yet)\n");

    let port = syscall::port_create();
    if port == u64::MAX {
        syscall::debug_puts(b"[bt_srv] port_create FAIL\n");
        syscall::exit(1);
    }
    if !syscall::ns_register(b"bluetooth", port) {
        syscall::debug_puts(b"[bt_srv] ns_register FAIL\n");
        syscall::exit(1);
    }
    syscall::debug_puts(b"[bt_srv] ready on port ");
    print_num(port);
    syscall::debug_puts(b"\n");

    loop {
        let msg = match syscall::recv_with_cap(port) {
            Some(m) => m,
            None => continue,
        };
        // For the scaffold every operation acks with NOT_IMPLEMENTED.
        // The point is to publish the protocol surface so that callers
        // can be written against a stable shape; real HCI code drops
        // in by replacing the match arms.
        let (rep_tag, rep_d0) = match msg.tag {
            BT_HCI_CMD => (BT_ERR, ERR_NOT_IMPLEMENTED),
            BT_HCI_EVT_SUBSCRIBE => (BT_ERR, ERR_NOT_IMPLEMENTED),
            BT_LE_ADV_START => (BT_ERR, ERR_NOT_IMPLEMENTED),
            BT_LE_ADV_STOP => (BT_ERR, ERR_NOT_IMPLEMENTED),
            BT_LE_SCAN_START => (BT_ERR, ERR_NOT_IMPLEMENTED),
            BT_LE_SCAN_STOP => (BT_ERR, ERR_NOT_IMPLEMENTED),
            BT_PAN_OPEN => (BT_ERR, ERR_NOT_IMPLEMENTED),
            _ => (BT_ERR, ERR_NOT_IMPLEMENTED),
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
