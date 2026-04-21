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

// --- Retransmission timer constants (RFC 4960 Section 6.3) ---
const RTO_INITIAL_US: u64 = 3_000_000;   // 3 seconds
const RTO_MIN_US: u64 = 1_000_000;       // 1 second
const RTO_MAX_US: u64 = 60_000_000;      // 60 seconds
const MAX_RETRANSMITS: u8 = 10;          // Max retransmissions before abort
const MAX_UNACKED_PKT: usize = 300;      // Max stored unacked packet size

// Built-in echo server port.
const ECHO_PORT: u16 = 7;

// --- Transport modes ---
const TRANSPORT_LOOPBACK: u8 = 0;
const TRANSPORT_UDP: u8 = 1;

// UDP encapsulation port (RFC 6951 default).
const UDP_ENCAP_PORT: u16 = 9899;

// IPC tags for talking to tcp4_srv (grant-page UDP).
const NET_UDP_BIND: u64 = 0x4900;
const NET_UDP_BIND_OK: u64 = 0x4901;
const NET_UDP_SEND_BUF: u64 = 0x4A10;
const NET_UDP_SEND_OK: u64 = 0x4A01;
const NET_UDP_RECV_BUF: u64 = 0x4B20;
const NET_UDP_DATA_BUF: u64 = 0x4B21;

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
    transport: u8,         // TRANSPORT_LOOPBACK or TRANSPORT_UDP
    // Local endpoint.
    local_port: u16,
    local_vtag: u32,       // Verification Tag we expect to receive
    // Remote endpoint.
    remote_port: u16,
    remote_vtag: u32,      // Verification Tag we send
    remote_ip: u32,        // Remote IP (big-endian for wire)
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
    // Retransmission timer state (RFC 4960 Section 6.3).
    rto_us: u64,           // Current RTO in microseconds
    t3_deadline_ns: u64,   // T3-rtx expiry (absolute ns, 0 = stopped)
    retransmit_count: u8,  // Number of retransmissions for current DATA
    unacked_tsn: u32,      // Lowest unacknowledged TSN
    unacked_pkt: [u8; MAX_UNACKED_PKT], // Stored packet for retransmission
    unacked_len: usize,    // Length of stored packet (0 = nothing to retransmit)
}

impl Association {
    const fn new() -> Self {
        Self {
            state: STATE_CLOSED,
            transport: TRANSPORT_LOOPBACK,
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
            rto_us: RTO_INITIAL_US,
            t3_deadline_ns: 0,
            retransmit_count: 0,
            unacked_tsn: 0,
            unacked_pkt: [0u8; MAX_UNACKED_PKT],
            unacked_len: 0,
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

    // Determine transport: loopback if remote is 127.0.0.1 or echo port, else UDP.
    let is_loopback = remote_ip == 0x7F000001 || remote_ip == 0;

    unsafe {
        let a = &mut ASSOCS[init_idx];
        a.state = STATE_COOKIE_WAIT;
        a.transport = if is_loopback { TRANSPORT_LOOPBACK } else { TRANSPORT_UDP };
        a.local_port = local_port;
        a.local_vtag = local_vtag;
        a.remote_port = remote_port;
        a.remote_ip = remote_ip;
        a.next_tsn = init_tsn;
        a.out_streams = num_out;
        a.in_streams = num_in;
        a.reply_port = reply_port;
    }

    if !is_loopback {
        // --- UDP transport: send INIT and return. Handshake completes async. ---
        if !unsafe { UDP_READY } {
            unsafe { ASSOCS[init_idx].reset(); }
            syscall::send(reply_port, SCTP_ASSOC_FAIL, 4, 0, 0, 0);
            return;
        }
        udp_initiate_association(init_idx, local_port, remote_port,
                                 local_vtag, num_out, num_in, init_tsn);
        return;
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

        // Check transport mode.
        let transport = a.transport;

        if transport == TRANSPORT_UDP {
            // UDP: serialize DATA chunk and send on wire.
            udp_send_data(assoc_id, &payload[..actual_len]);
        } else {
            // Loopback: deliver directly to the echo association.
            let tsn = a.next_tsn;
            a.next_tsn += 1;
            let ssn = a.streams[stream_id as usize % MAX_STREAMS].next_ssn_send;
            a.streams[stream_id as usize % MAX_STREAMS].next_ssn_send += 1;

            if let Some(echo_idx) = find_assoc_by_ports(a.remote_port, a.local_port) {
                deliver_data(echo_idx, tsn, stream_id, ssn, &payload[..actual_len]);
                // Process echo immediately.
                echo_process(echo_idx);
            }
            // SACK the send (loopback: instant ACK).
            a.cum_tsn_ack = tsn;
        }
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

        if a.transport == TRANSPORT_UDP && a.state == STATE_ESTABLISHED {
            // RFC 4960 Section 9.2: Initiate graceful shutdown over UDP.
            // Send SHUTDOWN chunk with cumulative TSN ack.
            let cum_tsn = a.rcv_next_tsn.wrapping_sub(1);
            let mut pkt = [0u8; 32];
            build_sctp_header(&mut pkt, a.local_port, a.remote_port, a.remote_vtag);
            let clen = build_shutdown_chunk(&mut pkt, 12, cum_tsn);
            let total = 12 + clen;
            stamp_sctp_checksum(&mut pkt, total);

            // Store for T2-shutdown retransmission (reuse T3 timer fields).
            a.unacked_pkt[..total].copy_from_slice(&pkt[..total]);
            a.unacked_len = total;
            a.retransmit_count = 0;
            a.rto_us = RTO_INITIAL_US;
            a.t3_deadline_ns = syscall::clock_gettime() + a.rto_us * 1000;

            a.state = STATE_SHUTDOWN_SENT;
            a.reply_port = reply_port; // Deferred reply on SHUTDOWN-COMPLETE

            udp_send_sctp(assoc_id, &pkt, total);
            syscall::debug_puts(b"  [sctp_srv] SHUTDOWN sent over UDP\n");
            return;
        }

        // Loopback: immediate shutdown.
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

fn print_hex8(v: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    syscall::debug_putchar(HEX[(v >> 4) as usize]);
    syscall::debug_putchar(HEX[(v & 0xF) as usize]);
}

fn print_hex32(v: u32) {
    syscall::debug_puts(b"0x");
    print_hex8((v >> 24) as u8);
    print_hex8((v >> 16) as u8);
    print_hex8((v >> 8) as u8);
    print_hex8(v as u8);
}

// ===================================================================
// Phase 2: UDP-encapsulated SCTP transport (RFC 6951).
// SCTP packets are serialized to wire format and sent inside UDP
// datagrams to port 9899, enabling interop with host usrsctp.
// ===================================================================

// --- UDP transport global state ---
static mut UDP_NET_PORT: u64 = 0;   // tcp4_srv service port
static mut UDP_BIND_ID: u64 = !0;   // UDP binding ID from tcp4_srv
static mut UDP_SEND_VA: usize = 0;  // Grant page for outgoing UDP (4096 bytes)
static mut UDP_RECV_VA: usize = 0;  // Grant page for incoming UDP (4096 bytes)
static mut UDP_READY: bool = false;
static mut MY_PORT: u64 = 0;        // Our IPC port (for UDP recv replies)

// --- CRC-32C (Castagnoli) for SCTP checksum (RFC 3309) ---

static CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F63B78;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &b in data {
        crc = CRC32C_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFFFFFF
}

/// Compute SCTP checksum: CRC-32C over the packet with the checksum field zeroed.
fn sctp_checksum(pkt: &[u8]) -> u32 {
    if pkt.len() < 12 { return 0; }
    // Zero the checksum field (bytes 8-11) for computation.
    let mut crc: u32 = 0xFFFFFFFF;
    for i in 0..pkt.len() {
        let b = if (8..12).contains(&i) { 0u8 } else { pkt[i] };
        crc = CRC32C_TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFFFFFF
}

// --- Wire-format helpers ---

fn put_u16_be(buf: &mut [u8], off: usize, val: u16) {
    buf[off] = (val >> 8) as u8;
    buf[off + 1] = val as u8;
}

fn put_u32_be(buf: &mut [u8], off: usize, val: u32) {
    buf[off] = (val >> 24) as u8;
    buf[off + 1] = (val >> 16) as u8;
    buf[off + 2] = (val >> 8) as u8;
    buf[off + 3] = val as u8;
}

fn get_u16_be(buf: &[u8], off: usize) -> u16 {
    ((buf[off] as u16) << 8) | (buf[off + 1] as u16)
}

fn get_u32_be(buf: &[u8], off: usize) -> u32 {
    ((buf[off] as u32) << 24) | ((buf[off + 1] as u32) << 16)
    | ((buf[off + 2] as u32) << 8) | (buf[off + 3] as u32)
}

/// Build SCTP common header (12 bytes).
fn build_sctp_header(buf: &mut [u8], src_port: u16, dst_port: u16, vtag: u32) {
    put_u16_be(buf, 0, src_port);
    put_u16_be(buf, 2, dst_port);
    put_u32_be(buf, 4, vtag);
    // Checksum will be filled in after all chunks are appended.
    put_u32_be(buf, 8, 0);
}

/// Stamp CRC-32C checksum into bytes 8-11 of an SCTP packet (little-endian).
fn stamp_sctp_checksum(buf: &mut [u8], total_len: usize) {
    let cksum = sctp_checksum(&buf[..total_len]);
    // SCTP CRC-32C is stored in little-endian byte order.
    buf[8] = cksum as u8;
    buf[9] = (cksum >> 8) as u8;
    buf[10] = (cksum >> 16) as u8;
    buf[11] = (cksum >> 24) as u8;
}

// --- Build wire-format SCTP chunks ---

/// Build INIT chunk. Returns total chunk length (20 bytes).
fn build_init_chunk(buf: &mut [u8], off: usize, init_tag: u32, a_rwnd: u32,
                    num_out: u16, num_in: u16, initial_tsn: u32) -> usize {
    buf[off] = CHUNK_INIT;
    buf[off + 1] = 0; // flags
    put_u16_be(buf, off + 2, 20); // length
    put_u32_be(buf, off + 4, init_tag);
    put_u32_be(buf, off + 8, a_rwnd);
    put_u16_be(buf, off + 12, num_out);
    put_u16_be(buf, off + 14, num_in);
    put_u32_be(buf, off + 16, initial_tsn);
    20
}

/// Build DATA chunk. Returns total chunk length (padded to 4).
fn build_data_chunk(buf: &mut [u8], off: usize, tsn: u32, stream_id: u16,
                    ssn: u16, ppid: u32, payload: &[u8]) -> usize {
    let chunk_len = 16 + payload.len();
    let padded = (chunk_len + 3) & !3;
    buf[off] = CHUNK_DATA;
    buf[off + 1] = 0x03; // B=1, E=1 (complete message in one chunk)
    put_u16_be(buf, off + 2, chunk_len as u16);
    put_u32_be(buf, off + 4, tsn);
    put_u16_be(buf, off + 8, stream_id);
    put_u16_be(buf, off + 10, ssn);
    put_u32_be(buf, off + 12, ppid);
    buf[off + 16..off + 16 + payload.len()].copy_from_slice(payload);
    // Zero padding.
    for i in chunk_len..padded {
        buf[off + i] = 0;
    }
    padded
}

/// Build COOKIE-ECHO chunk. Returns total chunk length.
fn build_cookie_echo_chunk(buf: &mut [u8], off: usize, cookie: &[u8]) -> usize {
    let chunk_len = 4 + cookie.len();
    let padded = (chunk_len + 3) & !3;
    buf[off] = CHUNK_COOKIE_ECHO;
    buf[off + 1] = 0;
    put_u16_be(buf, off + 2, chunk_len as u16);
    buf[off + 4..off + 4 + cookie.len()].copy_from_slice(cookie);
    for i in chunk_len..padded {
        buf[off + i] = 0;
    }
    padded
}

/// Build SACK chunk (16 bytes, no gap blocks or dup TSNs).
fn build_sack_chunk(buf: &mut [u8], off: usize, cum_tsn: u32, a_rwnd: u32) -> usize {
    buf[off] = CHUNK_SACK;
    buf[off + 1] = 0;
    put_u16_be(buf, off + 2, 16);
    put_u32_be(buf, off + 4, cum_tsn);
    put_u32_be(buf, off + 8, a_rwnd);
    put_u16_be(buf, off + 12, 0); // num gap blocks
    put_u16_be(buf, off + 14, 0); // num dup TSNs
    16
}

/// Build SHUTDOWN chunk (8 bytes).
fn build_shutdown_chunk(buf: &mut [u8], off: usize, cum_tsn: u32) -> usize {
    buf[off] = CHUNK_SHUTDOWN;
    buf[off + 1] = 0;
    put_u16_be(buf, off + 2, 8);
    put_u32_be(buf, off + 4, cum_tsn);
    8
}

/// Build SHUTDOWN-ACK chunk (4 bytes).
fn build_shutdown_ack_chunk(buf: &mut [u8], off: usize) -> usize {
    buf[off] = CHUNK_SHUTDOWN_ACK;
    buf[off + 1] = 0;
    put_u16_be(buf, off + 2, 4);
    4
}

/// Build SHUTDOWN-COMPLETE chunk (4 bytes).
fn build_shutdown_complete_chunk(buf: &mut [u8], off: usize) -> usize {
    buf[off] = CHUNK_SHUTDOWN_COMPLETE;
    buf[off + 1] = 0;
    put_u16_be(buf, off + 2, 4);
    4
}

// --- UDP transport send/recv ---

/// Send an SCTP packet via UDP encapsulation to the remote peer.
fn udp_send_sctp(assoc_idx: usize, pkt: &[u8], pkt_len: usize) {
    unsafe {
        if !UDP_READY { return; }
        let a = &ASSOCS[assoc_idx];
        // remote_ip is big-endian (e.g. 0x0A000202 = 10.0.2.2).
        // NET_UDP_SEND_BUF extracts bytes in little-endian order, so swap.
        let dst_ip_le = a.remote_ip.swap_bytes();
        let gva = UDP_SEND_VA;

        // Copy packet to send grant page (separate from recv page).
        let dst = gva as *mut u8;
        for i in 0..pkt_len {
            dst.add(i).write_volatile(pkt[i]);
        }

        // NET_UDP_SEND_BUF:
        // data[0] = dst_ip(low32) | dst_port(bits32-47) | bind_id(bits48-63)
        // data[1] = grant_va(low48) | payload_len(bits48-63)
        // data[2] = reply_port
        let d0 = (dst_ip_le as u64)
            | ((UDP_ENCAP_PORT as u64) << 32)
            | ((UDP_BIND_ID) << 48);
        let d1 = (gva as u64 & 0xFFFF_FFFF_FFFF) | ((pkt_len as u64) << 48);
        let rp = syscall::port_create();
        syscall::send(UDP_NET_PORT, NET_UDP_SEND_BUF, d0, d1, rp, 0);
        // Wait for send confirmation.
        let _ = syscall::recv_msg_timeout(rp, 500_000);
        syscall::port_destroy(rp);
    }
}

/// Post a grant-page UDP receive on our binding. Incoming data will
/// arrive as NET_UDP_DATA_BUF on our main IPC port.
fn udp_post_recv() {
    unsafe {
        if !UDP_READY { return; }
        // NET_UDP_RECV_BUF: data[0] = bind_id(low32) | reply_port(high32)
        //                   data[1] = grant_va (recv page, separate from send)
        let d0 = (UDP_BIND_ID & 0xFFFFFFFF) | (MY_PORT << 32);
        let d1 = UDP_RECV_VA as u64;
        syscall::send_nb_4(UDP_NET_PORT, NET_UDP_RECV_BUF, d0, d1, 0, 0);
    }
}

/// Initialize UDP transport: look up tcp4_srv ("net"), bind port 9899,
/// allocate a grant page.
fn udp_transport_init() -> bool {
    let net_port = match syscall::ns_lookup(b"net") {
        Some(p) => p,
        None => {
            syscall::debug_puts(b"  [sctp_srv] net service not found, UDP disabled\n");
            return false;
        }
    };

    // Allocate two grant pages: one for send, one for recv (avoids race).
    let send_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [sctp_srv] mmap_anon failed for UDP send page\n");
            return false;
        }
    };
    let recv_va = match syscall::mmap_anon(0, 1, 1) {
        Some(va) => va,
        None => {
            syscall::debug_puts(b"  [sctp_srv] mmap_anon failed for UDP recv page\n");
            return false;
        }
    };

    // Bind UDP port 9899.
    let rp = syscall::port_create();
    let d0 = (UDP_ENCAP_PORT as u64) | ((rp as u64) << 16);
    syscall::send_nb(net_port, NET_UDP_BIND, d0, 0);
    let reply = match syscall::recv_msg_timeout(rp, 2_000_000) {
        Some(m) => m,
        None => {
            syscall::debug_puts(b"  [sctp_srv] UDP bind timeout\n");
            syscall::port_destroy(rp);
            return false;
        }
    };
    syscall::port_destroy(rp);

    if reply.tag != NET_UDP_BIND_OK {
        syscall::debug_puts(b"  [sctp_srv] UDP bind failed\n");
        return false;
    }
    let bind_id = reply.data[0];

    // Grant both pages to tcp4_srv so it can read the send page and write the recv page.
    if !syscall::grant_pages(net_port, send_va, send_va, 1, false) {
        syscall::debug_puts(b"  [sctp_srv] UDP send grant failed\n");
        return false;
    }
    if !syscall::grant_pages(net_port, recv_va, recv_va, 1, false) {
        syscall::debug_puts(b"  [sctp_srv] UDP recv grant failed\n");
        return false;
    }

    unsafe {
        UDP_NET_PORT = net_port;
        UDP_BIND_ID = bind_id;
        UDP_SEND_VA = send_va;
        UDP_RECV_VA = recv_va;
        UDP_READY = true;
    }

    syscall::debug_puts(b"  [sctp_srv] UDP transport ready on port 9899\n");
    true
}

// --- UDP-mode association (async 4-way handshake) ---

/// Initiate an SCTP association over UDP. Sends INIT, then the handshake
/// completes asynchronously via handle_sctp_packet when replies arrive.
fn udp_initiate_association(
    init_idx: usize, local_port: u16, remote_port: u16,
    local_vtag: u32, num_out: u16, num_in: u16, init_tsn: u32,
) {
    // Build SCTP INIT packet.
    let mut pkt = [0u8; 64];
    // VTag=0 for INIT (RFC 4960 Section 8.5.1).
    build_sctp_header(&mut pkt, local_port, remote_port, 0);
    let clen = build_init_chunk(&mut pkt, 12, local_vtag, 65535, num_out, num_in, init_tsn);
    let total = 12 + clen;
    stamp_sctp_checksum(&mut pkt, total);

    udp_send_sctp(init_idx, &pkt, total);
    syscall::debug_puts(b"  [sctp_srv] sent INIT over UDP\n");
}

/// Process an incoming SCTP-over-UDP packet.
fn handle_sctp_packet(data: &[u8], data_len: usize, src_ip: u32, _src_port: u16) {
    if data_len < 12 { return; }

    let sctp_src_port = get_u16_be(data, 0);
    let sctp_dst_port = get_u16_be(data, 2);
    let vtag = get_u32_be(data, 4);
    // CRC-32C checksum is stored in little-endian.
    let wire_cksum = (data[8] as u32)
        | ((data[9] as u32) << 8)
        | ((data[10] as u32) << 16)
        | ((data[11] as u32) << 24);

    // Verify checksum.
    let calc_cksum = sctp_checksum(&data[..data_len]);
    if wire_cksum != calc_cksum {
        syscall::debug_puts(b"  [sctp_srv] bad SCTP cksum: len=");
        print_num(data_len as u64);
        syscall::debug_puts(b" wire=");
        print_hex32(wire_cksum);
        syscall::debug_puts(b" calc=");
        print_hex32(calc_cksum);
        syscall::debug_puts(b" hdr=");
        // Print first 16 bytes as hex for debugging.
        for i in 0..data_len.min(16) {
            print_hex8(data[i]);
        }
        syscall::debug_puts(b"\n");
        return;
    }

    // Parse chunks.
    let mut off = 12;
    while off + 4 <= data_len {
        let chunk_type = data[off];
        let chunk_flags = data[off + 1];
        let chunk_len = get_u16_be(data, off + 2) as usize;
        if chunk_len < 4 || off + chunk_len > data_len { break; }

        match chunk_type {
            CHUNK_INIT_ACK => {
                handle_rx_init_ack(data, off, chunk_len, sctp_src_port, sctp_dst_port);
            }
            CHUNK_COOKIE_ACK => {
                handle_rx_cookie_ack(sctp_src_port, sctp_dst_port);
            }
            CHUNK_DATA => {
                handle_rx_data(data, off, chunk_len, chunk_flags, sctp_src_port, sctp_dst_port, vtag);
            }
            CHUNK_SACK => {
                handle_rx_sack(data, off, chunk_len, sctp_src_port, sctp_dst_port);
            }
            CHUNK_HEARTBEAT => {
                handle_rx_heartbeat(data, off, chunk_len, sctp_src_port, sctp_dst_port, src_ip);
            }
            CHUNK_SHUTDOWN => {
                handle_rx_shutdown(data, off, chunk_len, sctp_src_port, sctp_dst_port);
            }
            CHUNK_SHUTDOWN_ACK => {
                handle_rx_shutdown_ack(sctp_src_port, sctp_dst_port);
            }
            CHUNK_SHUTDOWN_COMPLETE => {
                handle_rx_shutdown_complete(sctp_src_port, sctp_dst_port);
            }
            CHUNK_ABORT => {
                handle_rx_abort(sctp_src_port, sctp_dst_port);
            }
            _ => {
                // Unknown chunk — skip.
            }
        }

        // Advance to next chunk (padded to 4 bytes).
        off += (chunk_len + 3) & !3;
    }
}

fn handle_rx_init_ack(data: &[u8], off: usize, chunk_len: usize,
                      src_port: u16, dst_port: u16) {
    if chunk_len < 20 { return; }
    let init_tag = get_u32_be(data, off + 4);
    let a_rwnd = get_u32_be(data, off + 8);
    let num_out = get_u16_be(data, off + 12);
    let num_in = get_u16_be(data, off + 14);
    let initial_tsn = get_u32_be(data, off + 16);

    // Extract State Cookie parameter (type 0x0007).
    let mut cookie = [0u8; 256];
    let mut cookie_len = 0usize;
    let mut poff = off + 20;
    while poff + 4 <= off + chunk_len {
        let ptype = get_u16_be(data, poff);
        let plen = get_u16_be(data, poff + 2) as usize;
        if plen < 4 || poff + plen > off + chunk_len { break; }
        if ptype == 7 {
            // State Cookie.
            cookie_len = (plen - 4).min(256);
            cookie[..cookie_len].copy_from_slice(&data[poff + 4..poff + 4 + cookie_len]);
            break;
        }
        poff += (plen + 3) & !3;
    }

    if cookie_len == 0 {
        syscall::debug_puts(b"  [sctp_srv] INIT-ACK missing cookie\n");
        return;
    }

    // Find the initiator association in COOKIE_WAIT state.
    let idx = unsafe {
        let mut found = None;
        for i in 0..MAX_ASSOCIATIONS {
            if ASSOCS[i].state == STATE_COOKIE_WAIT
                && ASSOCS[i].local_port == dst_port
                && ASSOCS[i].remote_port == src_port
                && ASSOCS[i].transport == TRANSPORT_UDP
            {
                found = Some(i);
                break;
            }
        }
        found
    };

    let idx = match idx {
        Some(i) => i,
        None => return,
    };

    // Update association with responder's parameters.
    unsafe {
        let a = &mut ASSOCS[idx];
        a.remote_vtag = init_tag;
        a.peer_rwnd = a_rwnd;
        a.out_streams = a.out_streams.min(num_in);
        a.in_streams = a.in_streams.min(num_out);
        a.rcv_next_tsn = initial_tsn;
        a.state = STATE_COOKIE_ECHOED;
    }

    // Send COOKIE-ECHO.
    let mut pkt = [0u8; 300];
    let remote_vtag = unsafe { ASSOCS[idx].remote_vtag };
    let local_port = unsafe { ASSOCS[idx].local_port };
    build_sctp_header(&mut pkt, local_port, src_port, remote_vtag);
    let clen = build_cookie_echo_chunk(&mut pkt, 12, &cookie[..cookie_len]);
    let total = 12 + clen;
    stamp_sctp_checksum(&mut pkt, total);
    udp_send_sctp(idx, &pkt, total);
    syscall::debug_puts(b"  [sctp_srv] sent COOKIE-ECHO\n");
}

fn handle_rx_cookie_ack(src_port: u16, dst_port: u16) {
    let idx = unsafe {
        let mut found = None;
        for i in 0..MAX_ASSOCIATIONS {
            if ASSOCS[i].state == STATE_COOKIE_ECHOED
                && ASSOCS[i].local_port == dst_port
                && ASSOCS[i].remote_port == src_port
                && ASSOCS[i].transport == TRANSPORT_UDP
            {
                found = Some(i);
                break;
            }
        }
        found
    };

    let idx = match idx {
        Some(i) => i,
        None => return,
    };

    unsafe {
        let a = &mut ASSOCS[idx];
        a.state = STATE_ESTABLISHED;

        // Notify the waiting client.
        if a.reply_port != 0 {
            let d0 = (idx as u64) | ((a.local_port as u64) << 32);
            let d1 = (a.out_streams as u64) | ((a.in_streams as u64) << 16);
            syscall::send(a.reply_port, SCTP_ASSOCIATED, d0, d1, 0, 0);
            a.reply_port = 0;
        }
    }

    syscall::debug_puts(b"  [sctp_srv] UDP association ESTABLISHED\n");
}

fn handle_rx_data(data: &[u8], off: usize, chunk_len: usize, _flags: u8,
                  src_port: u16, dst_port: u16, _vtag: u32) {
    if chunk_len < 16 { return; }
    let tsn = get_u32_be(data, off + 4);
    let stream_id = get_u16_be(data, off + 8);
    let ssn = get_u16_be(data, off + 10);
    let _ppid = get_u32_be(data, off + 12);
    let payload_len = chunk_len - 16;

    let idx = unsafe {
        let mut found = None;
        for i in 0..MAX_ASSOCIATIONS {
            if ASSOCS[i].state == STATE_ESTABLISHED
                && ASSOCS[i].local_port == dst_port
                && ASSOCS[i].remote_port == src_port
                && ASSOCS[i].transport == TRANSPORT_UDP
            {
                found = Some(i);
                break;
            }
        }
        found
    };

    let idx = match idx {
        Some(i) => i,
        None => return,
    };

    // Deliver to receive buffer.
    deliver_data(idx, tsn, stream_id, ssn, &data[off + 16..off + 16 + payload_len]);

    // Send SACK.
    let cum_tsn = unsafe { ASSOCS[idx].rcv_next_tsn.wrapping_sub(1) };
    let local_port = unsafe { ASSOCS[idx].local_port };
    let remote_vtag = unsafe { ASSOCS[idx].remote_vtag };
    let mut pkt = [0u8; 32];
    build_sctp_header(&mut pkt, local_port, src_port, remote_vtag);
    let clen = build_sack_chunk(&mut pkt, 12, cum_tsn, 65535);
    let total = 12 + clen;
    stamp_sctp_checksum(&mut pkt, total);
    udp_send_sctp(idx, &pkt, total);

    // Wake pending recv if any.
    unsafe {
        if ASSOCS[idx].recv_reply_port != 0 {
            deliver_pending_recv(idx);
        }
    }
}

fn handle_rx_sack(data: &[u8], off: usize, chunk_len: usize,
                  src_port: u16, dst_port: u16) {
    if chunk_len < 12 { return; }
    let cum_tsn = get_u32_be(data, off + 4);

    let idx = unsafe {
        let mut found = None;
        for i in 0..MAX_ASSOCIATIONS {
            if ASSOCS[i].state == STATE_ESTABLISHED
                && ASSOCS[i].local_port == dst_port
                && ASSOCS[i].remote_port == src_port
                && ASSOCS[i].transport == TRANSPORT_UDP
            {
                found = Some(i);
                break;
            }
        }
        found
    };

    if let Some(i) = idx {
        unsafe {
            let a = &mut ASSOCS[i];
            a.cum_tsn_ack = cum_tsn;
            // If SACK acknowledges our unacked DATA, stop T3-rtx (RFC 4960 6.3.2 R3).
            if a.unacked_len > 0 && tsn_le(a.unacked_tsn, cum_tsn) {
                a.t3_deadline_ns = 0;
                a.unacked_len = 0;
                a.retransmit_count = 0;
                a.rto_us = RTO_INITIAL_US; // Reset RTO on successful ACK
            }
        }
    }
}

/// TSN comparison: a <= b (with wrapping, RFC 4960 serial arithmetic).
fn tsn_le(a: u32, b: u32) -> bool {
    let diff = b.wrapping_sub(a);
    diff == 0 || diff < 0x8000_0000
}

fn handle_rx_heartbeat(data: &[u8], off: usize, chunk_len: usize,
                       src_port: u16, dst_port: u16, _src_ip: u32) {
    // Reply with HEARTBEAT-ACK containing the same info.
    let idx = unsafe {
        let mut found = None;
        for i in 0..MAX_ASSOCIATIONS {
            if ASSOCS[i].state == STATE_ESTABLISHED
                && ASSOCS[i].local_port == dst_port
                && ASSOCS[i].remote_port == src_port
                && ASSOCS[i].transport == TRANSPORT_UDP
            {
                found = Some(i);
                break;
            }
        }
        found
    };

    let idx = match idx {
        Some(i) => i,
        None => return,
    };

    let remote_vtag = unsafe { ASSOCS[idx].remote_vtag };
    let local_port = unsafe { ASSOCS[idx].local_port };
    let mut pkt = [0u8; 300];
    build_sctp_header(&mut pkt, local_port, src_port, remote_vtag);
    // Copy the HB chunk, changing type to HEARTBEAT_ACK.
    let copy_len = chunk_len.min(280);
    pkt[12..12 + copy_len].copy_from_slice(&data[off..off + copy_len]);
    pkt[12] = CHUNK_HEARTBEAT_ACK;
    let total = 12 + ((copy_len + 3) & !3);
    stamp_sctp_checksum(&mut pkt, total);
    udp_send_sctp(idx, &pkt, total);
}

/// Handle incoming SHUTDOWN-ACK: we are the initiator (STATE_SHUTDOWN_SENT).
/// Send SHUTDOWN-COMPLETE, notify client, close association.
fn handle_rx_shutdown_ack(src_port: u16, dst_port: u16) {
    let idx = unsafe {
        let mut found = None;
        for i in 0..MAX_ASSOCIATIONS {
            if ASSOCS[i].state == STATE_SHUTDOWN_SENT
                && ASSOCS[i].local_port == dst_port
                && ASSOCS[i].remote_port == src_port
                && ASSOCS[i].transport == TRANSPORT_UDP
            {
                found = Some(i);
                break;
            }
        }
        found
    };

    let idx = match idx {
        Some(i) => i,
        None => return,
    };

    // Send SHUTDOWN-COMPLETE to peer.
    let remote_vtag = unsafe { ASSOCS[idx].remote_vtag };
    let local_port = unsafe { ASSOCS[idx].local_port };
    let mut pkt = [0u8; 16];
    build_sctp_header(&mut pkt, local_port, src_port, remote_vtag);
    let clen = build_shutdown_complete_chunk(&mut pkt, 12);
    let total = 12 + clen;
    stamp_sctp_checksum(&mut pkt, total);
    udp_send_sctp(idx, &pkt, total);

    syscall::debug_puts(b"  [sctp_srv] SHUTDOWN-ACK received, sent SHUTDOWN-COMPLETE\n");

    // Notify client that shutdown is complete.
    unsafe {
        let a = &mut ASSOCS[idx];
        let rp = a.reply_port;
        a.reply_port = 0;
        a.reset();
        if rp != 0 {
            syscall::send(rp, SCTP_SHUTDOWN_COMPLETE, idx as u64, 0, 0, 0);
        }
    }
}

/// Handle incoming SHUTDOWN from peer (peer-initiated shutdown).
/// Respond with SHUTDOWN-ACK.
fn handle_rx_shutdown(data: &[u8], off: usize, chunk_len: usize,
                      src_port: u16, dst_port: u16) {
    if chunk_len < 8 { return; }
    let _cum_tsn = get_u32_be(data, off + 4);

    let idx = unsafe {
        let mut found = None;
        for i in 0..MAX_ASSOCIATIONS {
            if ASSOCS[i].state == STATE_ESTABLISHED
                && ASSOCS[i].local_port == dst_port
                && ASSOCS[i].remote_port == src_port
                && ASSOCS[i].transport == TRANSPORT_UDP
            {
                found = Some(i);
                break;
            }
        }
        found
    };

    let idx = match idx {
        Some(i) => i,
        None => return,
    };

    // Send SHUTDOWN-ACK.
    let remote_vtag = unsafe { ASSOCS[idx].remote_vtag };
    let local_port = unsafe { ASSOCS[idx].local_port };
    let mut pkt = [0u8; 16];
    build_sctp_header(&mut pkt, local_port, src_port, remote_vtag);
    let clen = build_shutdown_ack_chunk(&mut pkt, 12);
    let total = 12 + clen;
    stamp_sctp_checksum(&mut pkt, total);

    unsafe { ASSOCS[idx].state = STATE_SHUTDOWN_ACK_SENT; }
    udp_send_sctp(idx, &pkt, total);

    syscall::debug_puts(b"  [sctp_srv] peer SHUTDOWN received, sent SHUTDOWN-ACK\n");
}

/// Handle incoming SHUTDOWN-COMPLETE (we are the responder, STATE_SHUTDOWN_ACK_SENT).
fn handle_rx_shutdown_complete(src_port: u16, dst_port: u16) {
    let idx = unsafe {
        let mut found = None;
        for i in 0..MAX_ASSOCIATIONS {
            if ASSOCS[i].state == STATE_SHUTDOWN_ACK_SENT
                && ASSOCS[i].local_port == dst_port
                && ASSOCS[i].remote_port == src_port
                && ASSOCS[i].transport == TRANSPORT_UDP
            {
                found = Some(i);
                break;
            }
        }
        found
    };

    if let Some(i) = idx {
        unsafe { ASSOCS[i].reset(); }
        syscall::debug_puts(b"  [sctp_srv] SHUTDOWN-COMPLETE received, association closed\n");
    }
}

fn handle_rx_abort(src_port: u16, dst_port: u16) {
    let idx = unsafe {
        let mut found = None;
        for i in 0..MAX_ASSOCIATIONS {
            if ASSOCS[i].state != STATE_CLOSED
                && ASSOCS[i].local_port == dst_port
                && ASSOCS[i].remote_port == src_port
                && ASSOCS[i].transport == TRANSPORT_UDP
            {
                found = Some(i);
                break;
            }
        }
        found
    };

    if let Some(i) = idx {
        unsafe {
            let a = &mut ASSOCS[i];
            if a.reply_port != 0 {
                syscall::send(a.reply_port, SCTP_ASSOC_FAIL, 3, 0, 0, 0);
                a.reply_port = 0;
            }
            a.reset();
        }
        syscall::debug_puts(b"  [sctp_srv] ABORT received, association closed\n");
    }
}

// --- Modified SEND for UDP transport ---

fn udp_send_data(assoc_idx: usize, payload: &[u8]) {
    unsafe {
        let a = &mut ASSOCS[assoc_idx];
        let tsn = a.next_tsn;
        a.next_tsn += 1;
        let stream_id = 0u16;
        let ssn = a.streams[0].next_ssn_send;
        a.streams[0].next_ssn_send += 1;

        let mut pkt = [0u8; 300];
        build_sctp_header(&mut pkt, a.local_port, a.remote_port, a.remote_vtag);
        let clen = build_data_chunk(&mut pkt, 12, tsn, stream_id, ssn, 0, payload);
        let total = 12 + clen;
        stamp_sctp_checksum(&mut pkt, total);

        // Store packet for T3-rtx retransmission (RFC 4960 Section 6.3.2).
        if total <= MAX_UNACKED_PKT {
            a.unacked_pkt[..total].copy_from_slice(&pkt[..total]);
            a.unacked_len = total;
            a.unacked_tsn = tsn;
            a.retransmit_count = 0;
            // Start T3-rtx timer.
            a.t3_deadline_ns = syscall::clock_gettime() + a.rto_us * 1000;
        }

        udp_send_sctp(assoc_idx, &pkt, total);
    }
}

// -------------------------------------------------------------------
// T3-rtx retransmission timer (RFC 4960 Section 6.3).
// -------------------------------------------------------------------

/// Check all associations for expired retransmission timers (T3-rtx and T2-shutdown).
fn check_retransmission_timers() {
    let now = syscall::clock_gettime();
    for i in 0..MAX_ASSOCIATIONS {
        unsafe {
            let a = &mut ASSOCS[i];
            if a.transport != TRANSPORT_UDP {
                continue;
            }
            if a.state != STATE_ESTABLISHED && a.state != STATE_SHUTDOWN_SENT {
                continue;
            }
            if a.t3_deadline_ns == 0 || a.unacked_len == 0 {
                continue;
            }
            if now < a.t3_deadline_ns {
                continue;
            }

            // T3-rtx expired.
            a.retransmit_count += 1;
            if a.retransmit_count > MAX_RETRANSMITS {
                syscall::debug_puts(b"  [sctp_srv] T3-rtx: max retransmits, aborting assoc\n");
                if a.recv_reply_port != 0 {
                    syscall::send(a.recv_reply_port, SCTP_RECV_NONE, 0, 0, 0, 0);
                }
                if a.reply_port != 0 {
                    syscall::send(a.reply_port, SCTP_ASSOC_FAIL, 5, 0, 0, 0);
                }
                a.reset();
                continue;
            }

            // Exponential backoff: double RTO, clamped to RTO_MAX.
            a.rto_us = (a.rto_us * 2).min(RTO_MAX_US);

            // Retransmit the stored packet.
            let len = a.unacked_len;
            let mut pkt = [0u8; MAX_UNACKED_PKT];
            pkt[..len].copy_from_slice(&a.unacked_pkt[..len]);
            // Restart T3-rtx with new (doubled) RTO.
            a.t3_deadline_ns = syscall::clock_gettime() + a.rto_us * 1000;

            syscall::debug_puts(b"  [sctp_srv] T3-rtx: retransmit #");
            print_num(a.retransmit_count as u64);
            syscall::debug_puts(b" rto=");
            print_num(a.rto_us / 1000);
            syscall::debug_puts(b"ms\n");

            udp_send_sctp(i, &pkt, len);
        }
    }
}

/// Compute the next retransmission deadline across all associations (0 = no timer running).
/// Covers both T3-rtx (ESTABLISHED) and T2-shutdown (SHUTDOWN_SENT) timers.
fn next_t3_deadline_ns() -> u64 {
    let mut earliest: u64 = 0;
    for i in 0..MAX_ASSOCIATIONS {
        unsafe {
            let a = &ASSOCS[i];
            let has_timer = (a.state == STATE_ESTABLISHED || a.state == STATE_SHUTDOWN_SENT)
                && a.t3_deadline_ns != 0;
            if has_timer {
                if earliest == 0 || a.t3_deadline_ns < earliest {
                    earliest = a.t3_deadline_ns;
                }
            }
        }
    }
    earliest
}

// -------------------------------------------------------------------
// Main entry point.
// -------------------------------------------------------------------

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [sctp_srv] starting\n");

    // Register with name server.
    let port = syscall::port_create();
    unsafe { MY_PORT = port; }
    syscall::ns_register(b"sctp", port);
    syscall::debug_puts(b"  [sctp_srv] registered, echo on port 7\n");

    // Attempt to initialize UDP transport (non-fatal if net service not up yet).
    if udp_transport_init() {
        // Post first recv so we can receive incoming SCTP-over-UDP packets.
        udp_post_recv();
    }

    // Main service loop.
    // Uses timeout-based recv to support T3-rtx retransmission timers.
    loop {
        // Compute timeout: if a T3-rtx timer is running, wake at its deadline.
        let deadline = next_t3_deadline_ns();
        let msg_opt = if deadline != 0 {
            let now = syscall::clock_gettime();
            if now >= deadline {
                // Already expired — check timers immediately.
                check_retransmission_timers();
                // Try non-blocking recv after timer processing.
                syscall::recv_nb_msg(port)
            } else {
                let wait_us = (deadline - now) / 1000;
                syscall::recv_msg_timeout(port, wait_us.max(1))
            }
        } else {
            // No timers running — block indefinitely.
            syscall::recv_msg(port)
        };

        let msg = match msg_opt {
            Some(m) => m,
            None => {
                // Timeout — check retransmission timers.
                check_retransmission_timers();
                continue;
            }
        };

        match msg.tag {
            SCTP_ASSOCIATE => handle_associate(&msg),
            SCTP_SEND => handle_send(&msg),
            SCTP_RECV => handle_recv(&msg),
            SCTP_SHUTDOWN_REQ => handle_shutdown(&msg),
            SCTP_STAT => handle_stat(&msg),
            NET_UDP_DATA_BUF => {
                // Incoming SCTP-over-UDP packet.
                let plen = (msg.data[0] & 0xFFFF) as usize;
                let src_port = ((msg.data[0] >> 16) & 0xFFFF) as u16;
                // src_ip from tcp4_srv is in LE byte order; swap to BE.
                let src_ip_le = (msg.data[1] & 0xFFFFFFFF) as u32;
                let src_ip = src_ip_le.swap_bytes();
                // Read payload from recv grant page (separate from send page).
                let mut pkt = [0u8; 1400];
                let gva = unsafe { UDP_RECV_VA };
                let src = gva as *const u8;
                for i in 0..plen.min(1400) {
                    pkt[i] = unsafe { src.add(i).read_volatile() };
                }
                handle_sctp_packet(&pkt, plen.min(1400), src_ip, src_port);
                // Re-post recv for next packet.
                udp_post_recv();
            }
            _ => {}
        }
    }
}
