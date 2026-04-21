#![no_std]
#![no_main]

//! SCTP (Stream Control Transmission Protocol) server for Telix.
//!
//! Implements RFC 4960 SCTP with:
//! - 4-way handshake (INIT → INIT-ACK → COOKIE-ECHO → COOKIE-ACK)
//! - Multi-stream ordered delivery
//! - SACK-based reliable transport
//! - Built-in loopback echo server for self-testing (Phase 1)
//! - Future: UDP encapsulation (Phase 2) and raw IP (Phase 3)
//!
//! Architecture:
//!   client ←SCTP_CONNECT/SEND/RECV IPC→ sctp_srv ←loopback→ internal echo endpoint
//!
//! Registers as "sctp" in the Telix name server.

extern crate userlib;

use userlib::syscall;

// --- SCTP IPC tags (client ↔ sctp_srv) ---
const SCTP_ASSOCIATE: u64 = 0x4D00;
const SCTP_ASSOCIATED: u64 = 0x4D01;
const SCTP_ASSOC_FAIL: u64 = 0x4DFF;
const SCTP_SEND: u64 = 0x4E00;
const SCTP_SEND_OK: u64 = 0x4E01;
const SCTP_RECV: u64 = 0x4F00;
const SCTP_DATA: u64 = 0x4F01;
const SCTP_RECV_NONE: u64 = 0x4F12;
const SCTP_SHUTDOWN_REQ: u64 = 0x4D10;
const SCTP_SHUTDOWN_COMPLETE: u64 = 0x4D11;
const SCTP_ABORT_REQ: u64 = 0x4D20;
const SCTP_STAT: u64 = 0x4D30;
const SCTP_STAT_OK: u64 = 0x4D31;

// --- SCTP chunk types (RFC 4960 Section 3.2) ---
const CHUNK_DATA: u8 = 0;
const CHUNK_INIT: u8 = 1;
const CHUNK_INIT_ACK: u8 = 2;
const CHUNK_SACK: u8 = 3;
const CHUNK_HEARTBEAT: u8 = 4;
const CHUNK_HEARTBEAT_ACK: u8 = 5;
const CHUNK_ABORT: u8 = 6;
const CHUNK_SHUTDOWN: u8 = 7;
const CHUNK_SHUTDOWN_ACK: u8 = 8;
const CHUNK_ERROR: u8 = 9;
const CHUNK_COOKIE_ECHO: u8 = 10;
const CHUNK_COOKIE_ACK: u8 = 11;
const CHUNK_SHUTDOWN_COMPLETE: u8 = 14;

// --- SCTP association states (RFC 4960 Section 4) ---
const STATE_CLOSED: u8 = 0;
const STATE_COOKIE_WAIT: u8 = 1;
const STATE_COOKIE_ECHOED: u8 = 2;
const STATE_ESTABLISHED: u8 = 3;
const STATE_SHUTDOWN_PENDING: u8 = 4;
const STATE_SHUTDOWN_SENT: u8 = 5;
const STATE_SHUTDOWN_RECEIVED: u8 = 6;
const STATE_SHUTDOWN_ACK_SENT: u8 = 7;

// --- Configuration ---
const MAX_ASSOCIATIONS: usize = 8;
const MAX_STREAMS: usize = 4;
const RX_BUF_SIZE: usize = 1024;
const MAX_DATA_CHUNK_PAYLOAD: usize = 64; // Limited by IPC inline data
const COOKIE_KEY: u64 = 0x5C7B_C001_1E5E_C873;

// Built-in echo server port.
const ECHO_PORT: u16 = 7;

// --- Data structures ---

/// Per-stream state (ordered delivery).
#[derive(Copy, Clone)]
struct StreamState {
    next_ssn_send: u16,    // Next stream sequence number to send
    next_ssn_recv: u16,    // Next expected SSN for ordered delivery
}

/// Receive buffer entry (one DATA chunk's payload).
#[derive(Copy, Clone)]
struct RxEntry {
    valid: bool,
    tsn: u32,
    stream_id: u16,
    ssn: u16,
    len: u16,
    data: [u8; MAX_DATA_CHUNK_PAYLOAD],
}

/// SCTP association (one endpoint pair).
struct Association {
    state: u8,
    // Local endpoint.
    local_port: u16,
    local_vtag: u32,       // Verification Tag we expect to receive
    // Remote endpoint.
    remote_port: u16,
    remote_vtag: u32,      // Verification Tag we send
    remote_ip: u32,        // Remote IP (BE, for future Phase 2/3)
    // Sequence numbers.
    next_tsn: u32,         // Next TSN to assign to outbound DATA
    cum_tsn_ack: u32,      // Highest cumulative TSN ACK'd by peer
    peer_rwnd: u32,        // Peer's receiver window credit
    // Receive state.
    rcv_next_tsn: u32,     // Next expected inbound TSN
    // Stream state.
    out_streams: u16,
    in_streams: u16,
    streams: [StreamState; MAX_STREAMS],
    // Receive buffer.
    rx_buf: [RxEntry; 4],
    rx_count: usize,
    // IPC state.
    reply_port: u64,       // Client's port for async notifications
    recv_reply_port: u64,  // Pending SCTP_RECV caller (0 = none)
    // Cookie (for COOKIE-ECHO verification).
    cookie: u64,
}

impl Association {
    const fn new() -> Self {
        Self {
            state: STATE_CLOSED,
            local_port: 0,
            local_vtag: 0,
            remote_port: 0,
            remote_vtag: 0,
            remote_ip: 0,
            next_tsn: 1,
            cum_tsn_ack: 0,
            peer_rwnd: 65535,
            rcv_next_tsn: 0,
            out_streams: MAX_STREAMS as u16,
            in_streams: MAX_STREAMS as u16,
            streams: [StreamState { next_ssn_send: 0, next_ssn_recv: 0 }; MAX_STREAMS],
            rx_buf: [RxEntry {
                valid: false, tsn: 0, stream_id: 0, ssn: 0, len: 0,
                data: [0u8; MAX_DATA_CHUNK_PAYLOAD],
            }; 4],
            rx_count: 0,
            reply_port: 0,
            recv_reply_port: 0,
            cookie: 0,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

// --- Global state ---

static mut ASSOCS: [Association; MAX_ASSOCIATIONS] = {
    const INIT: Association = Association::new();
    [INIT; MAX_ASSOCIATIONS]
};

static mut NEXT_VTAG: u32 = 0x1234_0001;
static mut NEXT_LOCAL_PORT: u16 = 49152;

fn alloc_vtag() -> u32 {
    unsafe {
        let v = NEXT_VTAG;
        NEXT_VTAG = NEXT_VTAG.wrapping_add(0x0100_0001);
        v
    }
}

fn alloc_port() -> u16 {
    unsafe {
        let p = NEXT_LOCAL_PORT;
        NEXT_LOCAL_PORT = NEXT_LOCAL_PORT.wrapping_add(1);
        if NEXT_LOCAL_PORT == 0 { NEXT_LOCAL_PORT = 49152; }
        p
    }
}

fn find_assoc_slot() -> Option<usize> {
    unsafe {
        for i in 0..MAX_ASSOCIATIONS {
            if ASSOCS[i].state == STATE_CLOSED {
                return Some(i);
            }
        }
        None
    }
}

fn find_assoc_by_ports(local_port: u16, remote_port: u16) -> Option<usize> {
    unsafe {
        for i in 0..MAX_ASSOCIATIONS {
            if ASSOCS[i].state != STATE_CLOSED
                && ASSOCS[i].local_port == local_port
                && ASSOCS[i].remote_port == remote_port
            {
                return Some(i);
            }
        }
        None
    }
}

// --- Cookie generation/verification (simplified HMAC) ---

fn make_cookie(local_port: u16, remote_port: u16, local_vtag: u32, remote_vtag: u32) -> u64 {
    let mut h = COOKIE_KEY;
    h ^= (local_port as u64) | ((remote_port as u64) << 16);
    h ^= (local_vtag as u64) << 32;
    h ^= remote_vtag as u64;
    h = h.wrapping_mul(0x517CC1B727220A95);
    h ^ (h >> 32)
}

// -------------------------------------------------------------------
// SCTP protocol engine — chunk processing.
// This implements the "wire" protocol internally for loopback.
// -------------------------------------------------------------------

/// Process an incoming INIT chunk (we are the responder).
/// Returns the association index if we created one (COOKIE_WAIT on responder side
/// is skipped — we go straight to sending INIT-ACK with cookie).
fn handle_init_chunk(
    init_tag: u32,
    a_rwnd: u32,
    num_out_streams: u16,
    num_in_streams: u16,
    initial_tsn: u32,
    src_port: u16,
    dst_port: u16,
) -> Option<(usize, u64)> {
    // Only accept connections to the echo port for now.
    if dst_port != ECHO_PORT {
        return None;
    }

    // Find or allocate a slot for the responder side.
    let idx = find_assoc_slot()?;
    let local_vtag = alloc_vtag();

    unsafe {
        let a = &mut ASSOCS[idx];
        a.state = STATE_CLOSED; // Will move to ESTABLISHED after COOKIE-ACK
        a.local_port = dst_port;
        a.local_vtag = local_vtag;
        a.remote_port = src_port;
        a.remote_vtag = init_tag;
        a.remote_ip = 0x7F000001; // 127.0.0.1
        a.next_tsn = 1;
        a.cum_tsn_ack = 0;
        a.peer_rwnd = a_rwnd;
        a.rcv_next_tsn = initial_tsn;
        a.out_streams = num_in_streams.min(MAX_STREAMS as u16);
        a.in_streams = num_out_streams.min(MAX_STREAMS as u16);
        a.cookie = make_cookie(dst_port, src_port, local_vtag, init_tag);
    }

    // Return INIT-ACK parameters: (responder_idx, cookie)
    unsafe { Some((idx, ASSOCS[idx].cookie)) }
}

/// Process COOKIE-ECHO: verify the cookie and move to ESTABLISHED.
fn handle_cookie_echo(cookie: u64, src_port: u16, dst_port: u16) -> Option<usize> {
    // Find the responder association that generated this cookie.
    unsafe {
        for i in 0..MAX_ASSOCIATIONS {
            if ASSOCS[i].local_port == dst_port
                && ASSOCS[i].remote_port == src_port
                && ASSOCS[i].cookie == cookie
            {
                ASSOCS[i].state = STATE_ESTABLISHED;
                return Some(i);
            }
        }
    }
    None
}

/// Deliver a DATA chunk to an established association's receive buffer.
fn deliver_data(
    assoc_idx: usize,
    tsn: u32,
    stream_id: u16,
    ssn: u16,
    payload: &[u8],
) -> bool {
    unsafe {
        let a = &mut ASSOCS[assoc_idx];
        if a.state != STATE_ESTABLISHED { return false; }

        // Check TSN is expected (simplified: accept if >= rcv_next_tsn).
        if tsn_lt(tsn, a.rcv_next_tsn) {
            return true; // Duplicate, just ACK it.
        }

        // Store in receive buffer.
        if a.rx_count >= a.rx_buf.len() {
            return false; // Buffer full.
        }

        let slot = a.rx_count;
        a.rx_buf[slot].valid = true;
        a.rx_buf[slot].tsn = tsn;
        a.rx_buf[slot].stream_id = stream_id;
        a.rx_buf[slot].ssn = ssn;
        a.rx_buf[slot].len = payload.len().min(MAX_DATA_CHUNK_PAYLOAD) as u16;
        a.rx_buf[slot].data[..payload.len().min(MAX_DATA_CHUNK_PAYLOAD)]
            .copy_from_slice(&payload[..payload.len().min(MAX_DATA_CHUNK_PAYLOAD)]);
        a.rx_count += 1;

        // Advance cumulative TSN.
        if tsn == a.rcv_next_tsn {
            a.rcv_next_tsn += 1;
        }

        true
    }
}

/// TSN comparison: a < b in serial arithmetic (RFC 4960 Section 1.6).
fn tsn_lt(a: u32, b: u32) -> bool {
    (a != b) && ((a.wrapping_sub(b)) & 0x80000000 != 0)
}

// -------------------------------------------------------------------
// Loopback echo engine.
// When data arrives at the echo endpoint, echo it back to the sender.
// -------------------------------------------------------------------

/// Process data arriving at the echo server and generate echo response.
/// This simulates the "remote" side for loopback testing.
fn echo_process(echo_assoc_idx: usize) {
    unsafe {
        let a = &mut ASSOCS[echo_assoc_idx];
        if a.state != STATE_ESTABLISHED { return; }

        // Drain rx_buf and echo each entry back to the initiator.
        for slot in 0..a.rx_buf.len() {
            if !a.rx_buf[slot].valid { continue; }

            let stream_id = a.rx_buf[slot].stream_id;
            let len = a.rx_buf[slot].len as usize;
            let mut payload = [0u8; MAX_DATA_CHUNK_PAYLOAD];
            payload[..len].copy_from_slice(&a.rx_buf[slot].data[..len]);

            a.rx_buf[slot].valid = false;

            // Find the initiator association (reverse ports).
            if let Some(init_idx) = find_assoc_by_ports(a.remote_port, a.local_port) {
                let init_a = &mut ASSOCS[init_idx];
                if init_a.state == STATE_ESTABLISHED {
                    // Deliver echo data to initiator's rx buffer.
                    let tsn = init_a.rcv_next_tsn; // Expected TSN
                    let ssn = init_a.streams[stream_id as usize % MAX_STREAMS].next_ssn_recv;
                    deliver_data(init_idx, tsn, stream_id, ssn, &payload[..len]);
                    init_a.streams[stream_id as usize % MAX_STREAMS].next_ssn_recv += 1;

                    // If initiator has a pending recv, wake it.
                    if init_a.recv_reply_port != 0 {
                        deliver_pending_recv(init_idx);
                    }
                }
            }
        }
        a.rx_count = 0;
    }
}

/// Deliver buffered data to a waiting SCTP_RECV caller.
fn deliver_pending_recv(assoc_idx: usize) {
    unsafe {
        let a = &mut ASSOCS[assoc_idx];
        if a.recv_reply_port == 0 || a.rx_count == 0 { return; }

        // Find first valid entry.
        for slot in 0..a.rx_buf.len() {
            if !a.rx_buf[slot].valid { continue; }

            let len = a.rx_buf[slot].len as usize;
            let stream_id = a.rx_buf[slot].stream_id;

            // Pack data into IPC message (up to 24 bytes in data[1..3]).
            let mut d1: u64 = 0;
            let mut d2: u64 = 0;
            let mut d3: u64 = 0;
            for i in 0..len.min(8) {
                d1 |= (a.rx_buf[slot].data[i] as u64) << (i * 8);
            }
            for i in 0..len.saturating_sub(8).min(8) {
                d2 |= (a.rx_buf[slot].data[8 + i] as u64) << (i * 8);
            }
            for i in 0..len.saturating_sub(16).min(8) {
                d3 |= (a.rx_buf[slot].data[16 + i] as u64) << (i * 8);
            }

            // d0 = len(low16) | stream_id(bits16-31) | assoc_idx(bits32-47)
            let d0 = (len as u64) | ((stream_id as u64) << 16) | ((assoc_idx as u64) << 32);

            syscall::send(a.recv_reply_port, SCTP_DATA, d0, d1, d2, d3);
            a.recv_reply_port = 0;
            a.rx_buf[slot].valid = false;
            a.rx_count -= 1;
            return;
        }
    }
}

// -------------------------------------------------------------------
// IPC handler: SCTP_ASSOCIATE — initiate a new association.
// -------------------------------------------------------------------

/// Handle SCTP_ASSOCIATE request from client.
/// data[0] = remote_ip(low32) | remote_port(bits32-47)
/// data[1] = local_port(low16) | reply_port(high48)
/// data[2] = num_out_streams(low16) | num_in_streams(high16)
fn handle_associate(msg: &syscall::Message) {
    let remote_ip = (msg.data[0] & 0xFFFFFFFF) as u32;
    let remote_port = ((msg.data[0] >> 32) & 0xFFFF) as u16;
    let local_port_req = (msg.data[1] & 0xFFFF) as u16;
    let reply_port = msg.data[1] >> 16;
    let num_out = ((msg.data[2] & 0xFFFF) as u16).max(1).min(MAX_STREAMS as u16);
    let num_in = (((msg.data[2] >> 16) & 0xFFFF) as u16).max(1).min(MAX_STREAMS as u16);

    let local_port = if local_port_req != 0 { local_port_req } else { alloc_port() };

    // Allocate initiator association.
    let init_idx = match find_assoc_slot() {
        Some(i) => i,
        None => {
            syscall::send(reply_port, SCTP_ASSOC_FAIL, 0, 0, 0, 0);
            return;
        }
    };

    let local_vtag = alloc_vtag();
    let init_tsn: u32 = 1;

    unsafe {
        let a = &mut ASSOCS[init_idx];
        a.state = STATE_COOKIE_WAIT;
        a.local_port = local_port;
        a.local_vtag = local_vtag;
        a.remote_port = remote_port;
        a.remote_ip = remote_ip;
        a.next_tsn = init_tsn;
        a.out_streams = num_out;
        a.in_streams = num_in;
        a.reply_port = reply_port;
    }

    // --- Loopback 4-way handshake (all happens synchronously) ---

    // Step 1: Send INIT → handle_init_chunk processes it as the responder.
    let init_result = handle_init_chunk(
        local_vtag,   // initiator's tag (what responder will put in VTag)
        65535,        // a-rwnd
        num_out,
        num_in,
        init_tsn,
        local_port,
        remote_port,
    );

    let (echo_idx, cookie) = match init_result {
        Some(v) => v,
        None => {
            unsafe { ASSOCS[init_idx].reset(); }
            syscall::send(reply_port, SCTP_ASSOC_FAIL, 1, 0, 0, 0);
            return;
        }
    };

    // Step 2: Receive INIT-ACK — extract responder's VTag and cookie.
    unsafe {
        let a = &mut ASSOCS[init_idx];
        a.remote_vtag = ASSOCS[echo_idx].local_vtag;
        a.state = STATE_COOKIE_ECHOED;
        a.rcv_next_tsn = 1; // Responder's initial TSN
        a.cookie = cookie;
    }

    // Step 3: Send COOKIE-ECHO → verified by handle_cookie_echo.
    let echo_ok = handle_cookie_echo(cookie, local_port, remote_port);
    if echo_ok.is_none() {
        unsafe {
            ASSOCS[init_idx].reset();
            ASSOCS[echo_idx].reset();
        }
        syscall::send(reply_port, SCTP_ASSOC_FAIL, 2, 0, 0, 0);
        return;
    }

    // Step 4: Receive COOKIE-ACK — association established on both sides.
    unsafe {
        ASSOCS[init_idx].state = STATE_ESTABLISHED;
    }

    // Report success.
    // data[0] = assoc_id(low32) | local_port(bits32-47)
    // data[1] = num_out_streams(low16) | num_in_streams(high16)
    let d0 = (init_idx as u64) | ((local_port as u64) << 32);
    let d1 = (num_out as u64) | ((num_in as u64) << 16);
    syscall::send(reply_port, SCTP_ASSOCIATED, d0, d1, 0, 0);

    syscall::debug_puts(b"  [sctp_srv] association established (loopback echo)\n");
}

// -------------------------------------------------------------------
// IPC handler: SCTP_SEND — send data on a stream.
// -------------------------------------------------------------------

/// Handle SCTP_SEND request.
/// data[0] = assoc_id(low32) | stream_id(bits32-47) | reply_port(high16 unused)
/// data[1] = payload_len(low16) | reply_port(high48)
/// data[2..3] = payload (up to 16 bytes inline)
fn handle_send(msg: &syscall::Message) {
    let assoc_id = (msg.data[0] & 0xFFFFFFFF) as usize;
    let stream_id = ((msg.data[0] >> 32) & 0xFFFF) as u16;
    let payload_len = (msg.data[1] & 0xFFFF) as usize;
    let reply_port = msg.data[1] >> 16;

    if assoc_id >= MAX_ASSOCIATIONS {
        syscall::send(reply_port, SCTP_ASSOC_FAIL, 0, 0, 0, 0);
        return;
    }

    unsafe {
        let a = &mut ASSOCS[assoc_id];
        if a.state != STATE_ESTABLISHED {
            syscall::send(reply_port, SCTP_ASSOC_FAIL, 0, 0, 0, 0);
            return;
        }

        // Extract payload from data[2..3].
        let mut payload = [0u8; MAX_DATA_CHUNK_PAYLOAD];
        let actual_len = payload_len.min(16).min(MAX_DATA_CHUNK_PAYLOAD);
        let w0 = msg.data[2];
        let w1 = msg.data[3];
        for i in 0..actual_len.min(8) {
            payload[i] = (w0 >> (i * 8)) as u8;
        }
        for i in 0..actual_len.saturating_sub(8).min(8) {
            payload[8 + i] = (w1 >> (i * 8)) as u8;
        }

        // Assign TSN and SSN.
        let tsn = a.next_tsn;
        a.next_tsn += 1;
        let ssn = a.streams[stream_id as usize % MAX_STREAMS].next_ssn_send;
        a.streams[stream_id as usize % MAX_STREAMS].next_ssn_send += 1;

        // For loopback: deliver directly to the echo association.
        if let Some(echo_idx) = find_assoc_by_ports(a.remote_port, a.local_port) {
            deliver_data(echo_idx, tsn, stream_id, ssn, &payload[..actual_len]);
            // Process echo immediately.
            echo_process(echo_idx);
        }

        // SACK the send (loopback: instant ACK).
        a.cum_tsn_ack = tsn;
    }

    // Reply with SEND_OK.
    syscall::send(reply_port, SCTP_SEND_OK, assoc_id as u64, 0, 0, 0);
}

// -------------------------------------------------------------------
// IPC handler: SCTP_RECV — receive data from a stream.
// -------------------------------------------------------------------

/// Handle SCTP_RECV request.
/// data[0] = assoc_id(low32) | reply_port(high32)
fn handle_recv(msg: &syscall::Message) {
    let assoc_id = (msg.data[0] & 0xFFFFFFFF) as usize;
    let reply_port = msg.data[0] >> 32;

    if assoc_id >= MAX_ASSOCIATIONS {
        syscall::send(reply_port, SCTP_RECV_NONE, 0, 0, 0, 0);
        return;
    }

    unsafe {
        let a = &mut ASSOCS[assoc_id];
        if a.state != STATE_ESTABLISHED {
            syscall::send(reply_port, SCTP_RECV_NONE, 0, 0, 0, 0);
            return;
        }

        // Check if data is available.
        if a.rx_count > 0 {
            a.recv_reply_port = reply_port;
            deliver_pending_recv(assoc_id);
        } else {
            // No data — store pending recv for later delivery.
            a.recv_reply_port = reply_port;
        }
    }
}

// -------------------------------------------------------------------
// IPC handler: SCTP_SHUTDOWN_REQ — graceful shutdown.
// -------------------------------------------------------------------

fn handle_shutdown(msg: &syscall::Message) {
    let assoc_id = (msg.data[0] & 0xFFFFFFFF) as usize;
    let reply_port = msg.data[0] >> 32;

    if assoc_id >= MAX_ASSOCIATIONS {
        syscall::send(reply_port, SCTP_SHUTDOWN_COMPLETE, 0, 0, 0, 0);
        return;
    }

    unsafe {
        let a = &mut ASSOCS[assoc_id];
        // Find the echo peer and shut it down too.
        if let Some(echo_idx) = find_assoc_by_ports(a.remote_port, a.local_port) {
            ASSOCS[echo_idx].reset();
        }
        a.reset();
    }

    syscall::send(reply_port, SCTP_SHUTDOWN_COMPLETE, assoc_id as u64, 0, 0, 0);
}

// -------------------------------------------------------------------
// IPC handler: SCTP_STAT — query association state.
// -------------------------------------------------------------------

fn handle_stat(msg: &syscall::Message) {
    let assoc_id = (msg.data[0] & 0xFFFFFFFF) as usize;
    let reply_port = msg.data[0] >> 32;

    if assoc_id >= MAX_ASSOCIATIONS {
        syscall::send(reply_port, SCTP_STAT_OK, 0, 0, 0, 0);
        return;
    }

    unsafe {
        let a = &ASSOCS[assoc_id];
        // data[0] = state | num_active_assocs
        // data[1] = next_tsn | cum_tsn_ack
        // data[2] = out_streams | in_streams | rx_count
        let d0 = (a.state as u64) | ((count_active() as u64) << 8);
        let d1 = (a.next_tsn as u64) | ((a.cum_tsn_ack as u64) << 32);
        let d2 = (a.out_streams as u64)
            | ((a.in_streams as u64) << 16)
            | ((a.rx_count as u64) << 32);
        syscall::send(reply_port, SCTP_STAT_OK, d0, d1, d2, 0);
    }
}

fn count_active() -> u8 {
    unsafe {
        let mut n = 0u8;
        for i in 0..MAX_ASSOCIATIONS {
            if ASSOCS[i].state != STATE_CLOSED { n += 1; }
        }
        n
    }
}

// -------------------------------------------------------------------
// Debug helpers.
// -------------------------------------------------------------------

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

// -------------------------------------------------------------------
// Main entry point.
// -------------------------------------------------------------------

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [sctp_srv] starting\n");

    // Register with name server.
    let port = syscall::port_create();
    syscall::ns_register(b"sctp", port);
    syscall::debug_puts(b"  [sctp_srv] registered, echo on port 7\n");

    // Main service loop.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => continue,
        };

        match msg.tag {
            SCTP_ASSOCIATE => handle_associate(&msg),
            SCTP_SEND => handle_send(&msg),
            SCTP_RECV => handle_recv(&msg),
            SCTP_SHUTDOWN_REQ => handle_shutdown(&msg),
            SCTP_STAT => handle_stat(&msg),
            _ => {}
        }
    }
}
