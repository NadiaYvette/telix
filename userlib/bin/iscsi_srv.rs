#![no_std]
#![no_main]

//! iSCSI initiator server — storage-over-network block device.
//!
//! Connects to a remote iSCSI target via tcp4_srv, speaks the iSCSI protocol
//! (RFC 3720), and presents the standard block device interface (IO_READ/IO_WRITE)
//! to clients. From cache_srv's perspective, this LUN is indistinguishable from
//! a local NVMe namespace.
//!
//! Architecture:
//!   client (cache_srv) --IO_READ/IO_WRITE--> iscsi_srv --TCP--> tcp4_srv --net--> target
//!
//! Configuration: target IP is passed via spawn_with_arg (encoded as IPv4 BE u32).
//! Default target port 3260, IQN negotiated at login time.

extern crate userlib;

use userlib::syscall;

// Block device interface (presented upward).
const IO_CONNECT: u64 = 0x100;
const IO_CONNECT_OK: u64 = 0x101;
const IO_READ: u64 = 0x200;
const IO_READ_OK: u64 = 0x201;
const IO_WRITE: u64 = 0x300;
const IO_WRITE_OK: u64 = 0x301;
const IO_STAT: u64 = 0x400;
const IO_STAT_OK: u64 = 0x401;
const IO_CLOSE: u64 = 0x500;
const IO_ERROR: u64 = 0xF00;

// TCP client protocol (talking to tcp4_srv).
const NET_TCP_CONNECT: u64 = 0x4200;
const NET_TCP_CONNECTED: u64 = 0x4201;
const NET_TCP_FAIL: u64 = 0x42FF;
const NET_TCP_SEND: u64 = 0x4300;
const NET_TCP_SEND_OK: u64 = 0x4301;
const NET_TCP_RECV: u64 = 0x4400;
const NET_TCP_DATA: u64 = 0x4401;
const NET_TCP_CLOSED: u64 = 0x44FF;
const NET_TCP_RECV_NB: u64 = 0x4410;
const NET_TCP_RECV_NONE: u64 = 0x4412;
const NET_TCP_CLOSE: u64 = 0x4500;

// iSCSI PDU opcodes (initiator → target).
const ISCSI_OP_LOGIN_REQ: u8 = 0x03;
const ISCSI_OP_SCSI_CMD: u8 = 0x01;
const ISCSI_OP_LOGOUT_REQ: u8 = 0x06;
const ISCSI_OP_NOP_OUT: u8 = 0x00;

// iSCSI PDU opcodes (target → initiator).
const ISCSI_OP_LOGIN_RSP: u8 = 0x23;
const ISCSI_OP_SCSI_RSP: u8 = 0x21;
const ISCSI_OP_SCSI_DATA_IN: u8 = 0x25;
const ISCSI_OP_LOGOUT_RSP: u8 = 0x26;
const ISCSI_OP_NOP_IN: u8 = 0x20;
const ISCSI_OP_R2T: u8 = 0x31;

// SCSI opcodes.
const SCSI_OP_TEST_UNIT_READY: u8 = 0x00;
const SCSI_OP_INQUIRY: u8 = 0x12;
const SCSI_OP_READ_CAPACITY_10: u8 = 0x25;
const SCSI_OP_READ_10: u8 = 0x28;
const SCSI_OP_WRITE_10: u8 = 0x2A;

// iSCSI login stages.
const STAGE_SECURITY: u8 = 0; // SecurityNegotiation
const STAGE_OPERATIONAL: u8 = 1; // LoginOperationalNegotiation
const STAGE_FULL_FEATURE: u8 = 3; // FullFeaturePhase

// SCSI status codes.
const SCSI_STATUS_GOOD: u8 = 0x00;

// iSCSI BHS (Basic Header Segment) size.
const BHS_SIZE: usize = 48;

// Block size for iSCSI LUN (standard 512 bytes).
const BLOCK_SIZE: u32 = 512;

// QEMU SLIRP gateway / host address.
const TARGET_IP_DEFAULT: u32 = 0x0A000202; // 10.0.2.2 (host via SLIRP) in BE
const TARGET_PORT: u16 = 13260;

/// iSCSI session state.
struct IscsiSession {
    tcp_port: u64,       // tcp4_srv port
    conn_id: u64,        // TCP connection handle
    reply_port: u64,     // Port for all TCP replies (connect, send, recv)
    connected: bool,
    logged_in: bool,
    cmd_sn: u32,         // Command Sequence Number
    exp_stat_sn: u32,    // Expected Status Sequence Number
    itt: u32,            // Initiator Task Tag (incremented per command)
    isid: [u8; 6],       // Initiator Session ID
    tsih: u16,           // Target Session Identifying Handle
    capacity_blocks: u32, // LUN capacity in blocks (from READ_CAPACITY_10)
    block_size: u32,      // Logical block size
    target_ip: u32,       // Target IP (big-endian)
}

impl IscsiSession {
    const fn new() -> Self {
        Self {
            tcp_port: 0,
            conn_id: 0,
            reply_port: 0,
            connected: false,
            logged_in: false,
            cmd_sn: 1,
            exp_stat_sn: 0,
            itt: 1,
            isid: [0x00, 0x02, 0x3D, 0x00, 0x00, 0x01], // OUI format, unique
            tsih: 0,
            capacity_blocks: 0,
            block_size: BLOCK_SIZE,
            target_ip: TARGET_IP_DEFAULT,
        }
    }

    fn next_itt(&mut self) -> u32 {
        let t = self.itt;
        self.itt += 1;
        t
    }
}

// -------------------------------------------------------------------
// TCP helper: send raw bytes in 16-byte chunks.
// tcp4_srv uses explicit reply ports (not call/reply caps).
// Uses session's reply_port and recv_msg_timeout (matching init.rs pattern).
// -------------------------------------------------------------------

/// Timeout for TCP send/recv operations (5 seconds in microseconds).
const TCP_TIMEOUT_US: u64 = 5_000_000;

/// TCP receive buffer — tcp4_srv delivers up to 24 bytes per message,
/// but we may only need a fraction. Buffer the excess for the next read.
static mut RECV_BUF: [u8; 64] = [0u8; 64];
static mut RECV_BUF_LEN: usize = 0;
static mut RECV_BUF_POS: usize = 0;

/// Fetch bytes from tcp4_srv into the receive buffer.
fn tcp_refill(sess: &IscsiSession) -> bool {
    let rp = sess.reply_port;
    let d1 = rp << 16;
    syscall::send(sess.tcp_port, NET_TCP_RECV, sess.conn_id, d1, 0, 0);
    let msg = match syscall::recv_msg_timeout(rp, TCP_TIMEOUT_US) {
        Some(m) if m.tag == NET_TCP_DATA => m,
        _ => return false,
    };
    let n = (msg.data[0] & 0xFFFF) as usize;
    if n == 0 { return false; }
    // Unpack into RECV_BUF.
    unsafe {
        RECV_BUF_POS = 0;
        RECV_BUF_LEN = n.min(24);
        let words = [msg.data[1], msg.data[2], msg.data[3]];
        for i in 0..RECV_BUF_LEN {
            RECV_BUF[i] = (words[i / 8] >> ((i % 8) * 8)) as u8;
        }
    }
    true
}

fn tcp_send_bytes(sess: &IscsiSession, data: &[u8]) -> bool {
    let rp = sess.reply_port;
    let mut off = 0;
    while off < data.len() {
        let chunk = (data.len() - off).min(16);
        let mut w0: u64 = 0;
        let mut w1: u64 = 0;
        for i in 0..chunk.min(8) {
            w0 |= (data[off + i] as u64) << (i * 8);
        }
        for i in 0..chunk.saturating_sub(8).min(8) {
            w1 |= (data[off + 8 + i] as u64) << (i * 8);
        }
        // data[1] = length(low16) | reply_port(high48)
        let d1 = (chunk as u64) | (rp << 16);
        syscall::send(sess.tcp_port, NET_TCP_SEND, sess.conn_id, d1, w0, w1);
        // Wait for SEND_OK with timeout.
        match syscall::recv_msg_timeout(rp, TCP_TIMEOUT_US) {
            Some(m) if m.tag == NET_TCP_SEND_OK => {}
            _ => return false,
        }
        off += chunk;
    }
    true
}

// -------------------------------------------------------------------
// TCP helper: receive exactly `count` bytes (with timeout).
// Uses buffered reads to avoid losing data from tcp4_srv's 24-byte messages.
// -------------------------------------------------------------------

fn tcp_recv_exact(sess: &IscsiSession, buf: &mut [u8], count: usize) -> bool {
    let mut got = 0;
    while got < count {
        // Try to satisfy from buffer first.
        unsafe {
            let avail = RECV_BUF_LEN - RECV_BUF_POS;
            if avail > 0 {
                let take = avail.min(count - got);
                for i in 0..take {
                    if got + i < buf.len() {
                        buf[got + i] = RECV_BUF[RECV_BUF_POS + i];
                    }
                }
                RECV_BUF_POS += take;
                got += take;
                continue;
            }
        }
        // Buffer empty — fetch more from tcp4_srv.
        if !tcp_refill(sess) {
            return false;
        }
    }
    true
}

/// Discard exactly `count` bytes from the TCP stream.
fn tcp_discard(sess: &IscsiSession, count: usize) -> bool {
    let mut got = 0;
    while got < count {
        unsafe {
            let avail = RECV_BUF_LEN - RECV_BUF_POS;
            if avail > 0 {
                let take = avail.min(count - got);
                RECV_BUF_POS += take;
                got += take;
                continue;
            }
        }
        if !tcp_refill(sess) {
            return false;
        }
    }
    true
}

// -------------------------------------------------------------------
// iSCSI PDU construction.
// -------------------------------------------------------------------

/// Build a 48-byte BHS in `buf`. Caller sets opcode-specific fields after.
fn bhs_init(buf: &mut [u8; BHS_SIZE], opcode: u8, immediate: bool) {
    *buf = [0u8; BHS_SIZE];
    buf[0] = opcode | if immediate { 0x40 } else { 0 };
}

/// Set data segment length in BHS (bytes 5..8, big-endian 24-bit).
fn bhs_set_data_len(buf: &mut [u8; BHS_SIZE], len: u32) {
    buf[5] = ((len >> 16) & 0xFF) as u8;
    buf[6] = ((len >> 8) & 0xFF) as u8;
    buf[7] = (len & 0xFF) as u8;
}

/// Set ITT (bytes 16..20, big-endian).
fn bhs_set_itt(buf: &mut [u8; BHS_SIZE], itt: u32) {
    buf[16] = (itt >> 24) as u8;
    buf[17] = (itt >> 16) as u8;
    buf[18] = (itt >> 8) as u8;
    buf[19] = itt as u8;
}

/// Set CmdSN (bytes 24..28, big-endian).
fn bhs_set_cmdsn(buf: &mut [u8; BHS_SIZE], sn: u32) {
    buf[24] = (sn >> 24) as u8;
    buf[25] = (sn >> 16) as u8;
    buf[26] = (sn >> 8) as u8;
    buf[27] = sn as u8;
}

/// Set ExpStatSN (bytes 28..32, big-endian).
fn bhs_set_expstatsn(buf: &mut [u8; BHS_SIZE], sn: u32) {
    buf[28] = (sn >> 24) as u8;
    buf[29] = (sn >> 16) as u8;
    buf[30] = (sn >> 8) as u8;
    buf[31] = sn as u8;
}

/// Get 32-bit big-endian value from BHS at given offset.
fn bhs_get_u32(buf: &[u8], off: usize) -> u32 {
    ((buf[off] as u32) << 24)
        | ((buf[off + 1] as u32) << 16)
        | ((buf[off + 2] as u32) << 8)
        | (buf[off + 3] as u32)
}

/// Get data segment length from BHS (24-bit BE at offset 5).
fn bhs_get_data_len(buf: &[u8]) -> u32 {
    ((buf[5] as u32) << 16) | ((buf[6] as u32) << 8) | (buf[7] as u32)
}

// -------------------------------------------------------------------
// iSCSI Login phase.
// -------------------------------------------------------------------

/// Build login request key=value text data.
fn build_login_kvs(buf: &mut [u8], max: usize) -> usize {
    let kvs: &[&[u8]] = &[
        b"InitiatorName=iqn.2024-01.com.telix:initiator\0",
        b"TargetName=iqn.com.example.disk\0",
        b"SessionType=Normal\0",
        b"AuthMethod=None\0",
        b"HeaderDigest=None\0",
        b"DataDigest=None\0",
        b"MaxRecvDataSegmentLength=8192\0",
        b"InitialR2T=Yes\0",
        b"ImmediateData=No\0",
        b"MaxBurstLength=8192\0",
        b"FirstBurstLength=8192\0",
        b"DefaultTime2Wait=0\0",
        b"DefaultTime2Retain=0\0",
        b"MaxOutstandingR2T=1\0",
        b"MaxConnections=1\0",
    ];
    let mut off = 0;
    for kv in kvs {
        if off + kv.len() > max { break; }
        buf[off..off + kv.len()].copy_from_slice(kv);
        off += kv.len();
    }
    off
}

fn iscsi_login(sess: &mut IscsiSession) -> bool {
    // Build login request PDU.
    let mut bhs = [0u8; BHS_SIZE];
    bhs_init(&mut bhs, ISCSI_OP_LOGIN_REQ, true);

    // Flags: Transit=1, Continue=0, CSG=SecurityNegotiation, NSG=FullFeaturePhase
    // bit7=Transit, bit6=Continue, bits5-4=CSG, bits3-2=NSG
    bhs[1] = 0x87; // Transit=1, CSG=0(Security), NSG=3(FFP)

    // Version max/min (both 0x00 for RFC 3720).
    bhs[2] = 0x00; // version-max
    bhs[3] = 0x00; // version-min

    // ISID (bytes 8..14).
    bhs[8] = sess.isid[0];
    bhs[9] = sess.isid[1];
    bhs[10] = sess.isid[2];
    bhs[11] = sess.isid[3];
    bhs[12] = sess.isid[4];
    bhs[13] = sess.isid[5];

    // TSIH (bytes 14..16) = 0 for new session.
    bhs[14] = 0;
    bhs[15] = 0;

    let itt = sess.next_itt();
    bhs_set_itt(&mut bhs, itt);
    bhs_set_cmdsn(&mut bhs, sess.cmd_sn);
    bhs_set_expstatsn(&mut bhs, sess.exp_stat_sn);

    // Build text key=value data segment.
    let mut data_buf = [0u8; 512];
    let data_len = build_login_kvs(&mut data_buf, 512);
    bhs_set_data_len(&mut bhs, data_len as u32);

    // Send BHS.
    if !tcp_send_bytes(sess, &bhs) {
        syscall::debug_puts(b"  [iscsi] login: send BHS failed\n");
        return false;
    }

    // Send data segment (padded to 4-byte boundary).
    let padded_len = (data_len + 3) & !3;
    // Zero-fill padding.
    for i in data_len..padded_len {
        data_buf[i] = 0;
    }
    if padded_len > 0 && !tcp_send_bytes(sess, &data_buf[..padded_len]) {
        syscall::debug_puts(b"  [iscsi] login: send data failed\n");
        return false;
    }

    // Receive login response BHS.
    let mut rsp = [0u8; BHS_SIZE];
    if !tcp_recv_exact(sess, &mut rsp, BHS_SIZE) {
        syscall::debug_puts(b"  [iscsi] login: recv BHS failed\n");
        return false;
    }

    let opcode = rsp[0] & 0x3F;
    if opcode != ISCSI_OP_LOGIN_RSP {
        syscall::debug_puts(b"  [iscsi] login: unexpected opcode\n");
        return false;
    }

    // Check status class (byte 36) and detail (byte 37).
    let status_class = rsp[36];
    if status_class != 0 {
        syscall::debug_puts(b"  [iscsi] login: rejected (status!=0)\n");
        return false;
    }

    // Extract StatSN (bytes 24..28) and update ExpStatSN.
    let stat_sn = bhs_get_u32(&rsp, 24);
    sess.exp_stat_sn = stat_sn + 1;

    // Extract TSIH (bytes 14..16).
    sess.tsih = ((rsp[14] as u16) << 8) | (rsp[15] as u16);

    // Check transit bit — if set, we're in FFP.
    let transit = (rsp[1] & 0x80) != 0;

    // Consume response data segment.
    let rsp_data_len = bhs_get_data_len(&rsp);
    if rsp_data_len > 0 {
        let padded = ((rsp_data_len as usize) + 3) & !3;
        tcp_discard(sess, padded);
    }

    if !transit {
        // Multi-stage login not implemented — target wants more negotiation.
        syscall::debug_puts(b"  [iscsi] login: multi-stage not impl\n");
        return false;
    }

    sess.cmd_sn += 1;
    sess.logged_in = true;
    syscall::debug_puts(b"  [iscsi] login: success (FFP)\n");
    true
}

// -------------------------------------------------------------------
// SCSI commands over iSCSI.
// -------------------------------------------------------------------

/// Send a SCSI command and receive the response. Returns (status, data_len).
/// For READ commands, `data_out` receives the read data.
/// For WRITE commands, `data_in` is the write payload sent after R2T.
fn scsi_command(
    sess: &mut IscsiSession,
    cdb: &[u8; 16],
    data_out: &mut [u8],       // buffer for data-in (reads)
    data_in: &[u8],            // data-out payload (writes)
    expected_data_len: u32,
    is_read: bool,
    is_write: bool,
) -> Option<u8> {
    let mut bhs = [0u8; BHS_SIZE];
    bhs_init(&mut bhs, ISCSI_OP_SCSI_CMD, true);

    // Flags byte (byte 1):
    // bit7 = Final (always 1 for single-PDU commands)
    // bits6-5: Read=1,Write=0 for reads; Read=0,Write=1 for writes
    let mut flags: u8 = 0x80; // Final
    if is_read { flags |= 0x40; }  // Read bit
    if is_write { flags |= 0x20; } // Write bit
    bhs[1] = flags;

    // Total AHS length = 0.
    bhs[4] = 0;

    // Data segment length = 0 (no immediate data; we use R2T for writes).
    bhs_set_data_len(&mut bhs, 0);

    // LUN (bytes 8..16) — use LUN 0.
    // For single-level LUN addressing: byte 9 = LUN number.
    bhs[8] = 0; // LUN format
    bhs[9] = 0; // LUN 0

    let itt = sess.next_itt();
    bhs_set_itt(&mut bhs, itt);

    // Expected Data Transfer Length (bytes 20..24, BE).
    bhs[20] = (expected_data_len >> 24) as u8;
    bhs[21] = (expected_data_len >> 16) as u8;
    bhs[22] = (expected_data_len >> 8) as u8;
    bhs[23] = expected_data_len as u8;

    bhs_set_cmdsn(&mut bhs, sess.cmd_sn);
    bhs_set_expstatsn(&mut bhs, sess.exp_stat_sn);

    // CDB (bytes 32..48).
    bhs[32..48].copy_from_slice(cdb);

    // Send the command PDU.
    if !tcp_send_bytes(sess, &bhs) {
        return None;
    }
    sess.cmd_sn += 1;

    // Receive response PDU(s).
    // For reads: may get Data-In PDUs followed by SCSI Response.
    // For writes: may get R2T, we send Data-Out, then SCSI Response.
    let mut data_offset = 0usize;
    let mut scsi_status = 0u8;

    loop {
        let mut rsp = [0u8; BHS_SIZE];
        if !tcp_recv_exact(sess, &mut rsp, BHS_SIZE) {
            return None;
        }

        let opcode = rsp[0] & 0x3F;
        let rsp_data_len = bhs_get_data_len(&rsp) as usize;
        let padded_data = (rsp_data_len + 3) & !3;

        match opcode {
            ISCSI_OP_SCSI_DATA_IN => {
                // Data-In: contains read data.
                // Buffer Offset at bytes 40..44 (BE).
                let buf_off = bhs_get_u32(&rsp, 40) as usize;
                // Read data segment into data_out.
                let read_target = &mut data_out[buf_off..];
                let to_read = rsp_data_len.min(read_target.len());
                if to_read > 0 {
                    if !tcp_recv_exact(sess, &mut read_target[..to_read], to_read) {
                        return None;
                    }
                }
                // Discard any padding.
                if padded_data > to_read {
                    tcp_discard(sess, padded_data - to_read);
                }
                data_offset += rsp_data_len;

                // Check S-bit (Status bit, byte 1 bit 0) — if set, contains status.
                if rsp[1] & 0x01 != 0 {
                    scsi_status = rsp[3]; // Status field in Data-In with S=1
                    // Update StatSN.
                    let stat_sn = bhs_get_u32(&rsp, 24);
                    sess.exp_stat_sn = stat_sn + 1;
                    break;
                }
            }
            ISCSI_OP_SCSI_RSP => {
                // SCSI Response PDU.
                scsi_status = rsp[3]; // Status byte
                let stat_sn = bhs_get_u32(&rsp, 24);
                sess.exp_stat_sn = stat_sn + 1;

                // Consume any response data (sense data etc).
                if padded_data > 0 {
                    tcp_discard(sess, padded_data);
                }
                break;
            }
            ISCSI_OP_R2T => {
                // Ready To Transfer — target wants us to send write data.
                let r2t_offset = bhs_get_u32(&rsp, 40) as usize;
                let r2t_len = bhs_get_u32(&rsp, 44) as usize;
                let ttt = bhs_get_u32(&rsp, 20); // Target Transfer Tag

                // Update StatSN (R2T carries StatSN).
                let stat_sn = bhs_get_u32(&rsp, 24);
                sess.exp_stat_sn = stat_sn + 1;

                // Build and send Data-Out PDU.
                let actual_len = r2t_len.min(data_in.len().saturating_sub(r2t_offset));
                let mut dout_bhs = [0u8; BHS_SIZE];
                dout_bhs[0] = 0x05; // SCSI Data-Out opcode
                dout_bhs[1] = 0x80; // Final bit
                bhs_set_data_len(&mut dout_bhs, actual_len as u32);
                // LUN.
                dout_bhs[8] = 0;
                dout_bhs[9] = 0;
                // ITT (same as command).
                dout_bhs[16] = (itt >> 24) as u8;
                dout_bhs[17] = (itt >> 16) as u8;
                dout_bhs[18] = (itt >> 8) as u8;
                dout_bhs[19] = itt as u8;
                // TTT.
                dout_bhs[20] = (ttt >> 24) as u8;
                dout_bhs[21] = (ttt >> 16) as u8;
                dout_bhs[22] = (ttt >> 8) as u8;
                dout_bhs[23] = ttt as u8;
                // ExpStatSN.
                bhs_set_expstatsn(&mut dout_bhs, sess.exp_stat_sn);
                // DataSN (offset 36..40).
                dout_bhs[36] = 0; dout_bhs[37] = 0; dout_bhs[38] = 0; dout_bhs[39] = 0;
                // Buffer Offset.
                dout_bhs[40] = (r2t_offset >> 24) as u8;
                dout_bhs[41] = (r2t_offset >> 16) as u8;
                dout_bhs[42] = (r2t_offset >> 8) as u8;
                dout_bhs[43] = r2t_offset as u8;

                if !tcp_send_bytes(sess, &dout_bhs) {
                    return None;
                }
                // Send data payload (padded to 4 bytes).
                let padded_out = (actual_len + 3) & !3;
                // We send the actual data, then pad bytes.
                if actual_len > 0 {
                    if !tcp_send_bytes(sess, &data_in[r2t_offset..r2t_offset + actual_len]) {
                        return None;
                    }
                }
                let pad = padded_out - actual_len;
                if pad > 0 {
                    let zeros = [0u8; 4];
                    if !tcp_send_bytes(sess, &zeros[..pad]) {
                        return None;
                    }
                }
            }
            ISCSI_OP_NOP_IN => {
                // NOP-In from target (keepalive). If TTT != 0xFFFFFFFF, reply.
                let ttt = bhs_get_u32(&rsp, 20);
                if padded_data > 0 { tcp_discard(sess, padded_data); }
                if ttt != 0xFFFFFFFF {
                    // Send NOP-Out in reply.
                    let mut nop = [0u8; BHS_SIZE];
                    bhs_init(&mut nop, ISCSI_OP_NOP_OUT, true);
                    nop[1] = 0x80; // Final
                    bhs_set_itt(&mut nop, 0xFFFFFFFF); // unsolicited
                    // TTT = target's TTT.
                    nop[20] = (ttt >> 24) as u8;
                    nop[21] = (ttt >> 16) as u8;
                    nop[22] = (ttt >> 8) as u8;
                    nop[23] = ttt as u8;
                    bhs_set_cmdsn(&mut nop, sess.cmd_sn);
                    bhs_set_expstatsn(&mut nop, sess.exp_stat_sn);
                    let _ = tcp_send_bytes(sess, &nop);
                }
            }
            _ => {
                // Unknown opcode — discard data and continue.
                if padded_data > 0 { tcp_discard(sess, padded_data); }
            }
        }
    }

    Some(scsi_status)
}

/// Issue SCSI READ_CAPACITY(10) to get LUN size.
fn read_capacity(sess: &mut IscsiSession) -> bool {
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_OP_READ_CAPACITY_10;

    let mut data = [0u8; 8]; // Returns 8 bytes: last_lba(4) + block_size(4)
    match scsi_command(sess, &cdb, &mut data, &[], 8, true, false) {
        Some(SCSI_STATUS_GOOD) => {
            let last_lba = ((data[0] as u32) << 24)
                | ((data[1] as u32) << 16)
                | ((data[2] as u32) << 8)
                | (data[3] as u32);
            let bs = ((data[4] as u32) << 24)
                | ((data[5] as u32) << 16)
                | ((data[6] as u32) << 8)
                | (data[7] as u32);
            sess.capacity_blocks = last_lba + 1;
            sess.block_size = if bs > 0 { bs } else { BLOCK_SIZE };
            syscall::debug_puts(b"  [iscsi] capacity: ");
            print_num((sess.capacity_blocks as u64) * (sess.block_size as u64));
            syscall::debug_puts(b" bytes\n");
            true
        }
        _ => {
            syscall::debug_puts(b"  [iscsi] READ_CAPACITY failed\n");
            false
        }
    }
}

/// Issue SCSI TEST_UNIT_READY.
fn test_unit_ready(sess: &mut IscsiSession) -> bool {
    let cdb = [SCSI_OP_TEST_UNIT_READY, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut dummy = [0u8; 0];
    matches!(scsi_command(sess, &cdb, &mut dummy, &[], 0, false, false), Some(SCSI_STATUS_GOOD))
}

// -------------------------------------------------------------------
// Block I/O handlers.
// -------------------------------------------------------------------

/// Handle IO_READ: read blocks from the iSCSI target.
fn handle_io_read(sess: &mut IscsiSession, msg: &syscall::Message) {
    let offset = msg.data[1]; // byte offset
    let len = (msg.data[2] & 0xFFFFFFFF) as u32;
    let reply_port = msg.data[2] >> 32;
    let grant_va = msg.data[3] as usize;

    let lba = (offset / sess.block_size as u64) as u32;
    let block_count = ((len + sess.block_size - 1) / sess.block_size) as u16;
    let transfer_len = (block_count as u32) * sess.block_size;

    // Build READ(10) CDB.
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_OP_READ_10;
    cdb[2] = (lba >> 24) as u8;
    cdb[3] = (lba >> 16) as u8;
    cdb[4] = (lba >> 8) as u8;
    cdb[5] = lba as u8;
    cdb[7] = (block_count >> 8) as u8;
    cdb[8] = block_count as u8;

    // Use a static buffer for data (max 8KB per read to keep stack reasonable).
    static mut READ_BUF: [u8; 8192] = [0u8; 8192];
    let actual = (transfer_len as usize).min(8192);

    let status = unsafe {
        scsi_command(sess, &cdb, &mut READ_BUF[..actual], &[], transfer_len, true, false)
    };

    match status {
        Some(SCSI_STATUS_GOOD) => {
            if grant_va != 0 {
                // Copy data to grant page.
                unsafe {
                    let dst = grant_va as *mut u8;
                    for i in 0..actual.min(len as usize) {
                        dst.add(i).write_volatile(READ_BUF[i]);
                    }
                }
                syscall::send(reply_port, IO_READ_OK, len as u64, 0, 0, 0);
            } else {
                // Inline response (up to 24 bytes in data[1..3]).
                let mut d1: u64 = 0;
                let mut d2: u64 = 0;
                let mut d3: u64 = 0;
                let inline_len = actual.min(24);
                unsafe {
                    for i in 0..inline_len.min(8) {
                        d1 |= (READ_BUF[i] as u64) << (i * 8);
                    }
                    for i in 0..inline_len.saturating_sub(8).min(8) {
                        d2 |= (READ_BUF[8 + i] as u64) << (i * 8);
                    }
                    for i in 0..inline_len.saturating_sub(16).min(8) {
                        d3 |= (READ_BUF[16 + i] as u64) << (i * 8);
                    }
                }
                syscall::send(reply_port, IO_READ_OK, inline_len as u64, d1, d2, d3);
            }
        }
        _ => {
            syscall::send(reply_port, IO_ERROR, 1, 0, 0, 0);
        }
    }
}

/// Handle IO_WRITE: write blocks to the iSCSI target.
fn handle_io_write(sess: &mut IscsiSession, msg: &syscall::Message) {
    let offset = msg.data[1]; // byte offset
    let len = (msg.data[2] & 0xFFFFFFFF) as u32;
    let reply_port = msg.data[2] >> 32;
    let grant_va = msg.data[3] as usize;

    let lba = (offset / sess.block_size as u64) as u32;
    let block_count = ((len + sess.block_size - 1) / sess.block_size) as u16;
    let transfer_len = (block_count as u32) * sess.block_size;

    // Read data from grant page into our buffer.
    static mut WRITE_BUF: [u8; 8192] = [0u8; 8192];
    let actual = (transfer_len as usize).min(8192);

    unsafe {
        if grant_va != 0 {
            let src = grant_va as *const u8;
            for i in 0..actual.min(len as usize) {
                WRITE_BUF[i] = src.add(i).read_volatile();
            }
        }
    }

    // Build WRITE(10) CDB.
    let mut cdb = [0u8; 16];
    cdb[0] = SCSI_OP_WRITE_10;
    cdb[2] = (lba >> 24) as u8;
    cdb[3] = (lba >> 16) as u8;
    cdb[4] = (lba >> 8) as u8;
    cdb[5] = lba as u8;
    cdb[7] = (block_count >> 8) as u8;
    cdb[8] = block_count as u8;

    let status = unsafe {
        let mut dummy = [0u8; 0];
        scsi_command(sess, &cdb, &mut dummy, &WRITE_BUF[..actual], transfer_len, false, true)
    };

    match status {
        Some(SCSI_STATUS_GOOD) => {
            syscall::send(reply_port, IO_WRITE_OK, len as u64, 0, 0, 0);
        }
        _ => {
            syscall::send(reply_port, IO_ERROR, 1, 0, 0, 0);
        }
    }
}

// -------------------------------------------------------------------
// Debug printing.
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

fn print_ip(ip: u32) {
    print_num(((ip >> 24) & 0xFF) as u64);
    syscall::debug_putchar(b'.');
    print_num(((ip >> 16) & 0xFF) as u64);
    syscall::debug_putchar(b'.');
    print_num(((ip >> 8) & 0xFF) as u64);
    syscall::debug_putchar(b'.');
    print_num((ip & 0xFF) as u64);
}

// -------------------------------------------------------------------
// Main entry point.
// -------------------------------------------------------------------

#[unsafe(no_mangle)]
fn main(arg0: u64, _arg1: u64, _arg2: u64) {
    syscall::debug_puts(b"  [iscsi_srv] starting\n");

    // arg0 = target IP (big-endian u32), or 0 for default (10.0.2.2).
    let target_ip = if arg0 != 0 { arg0 as u32 } else { TARGET_IP_DEFAULT };

    // Look up tcp4_srv (registered as "net").
    let tcp_port = loop {
        match syscall::ns_lookup(b"net") {
            Some(p) => break p,
            None => syscall::yield_now(),
        }
    };

    let mut sess = IscsiSession::new();
    sess.tcp_port = tcp_port;
    sess.target_ip = target_ip;
    sess.reply_port = syscall::port_create();

    syscall::debug_puts(b"  [iscsi_srv] connecting to ");
    print_ip(target_ip);
    syscall::debug_puts(b":");
    print_num(TARGET_PORT as u64);
    syscall::debug_puts(b"\n");

    // Establish TCP connection to target.
    // Use same reply_port for connect and all subsequent TCP ops (matches init.rs pattern).
    let d0 = target_ip as u64;
    let d1 = (TARGET_PORT as u64) | ((sess.reply_port as u64) << 16);
    syscall::send(tcp_port, NET_TCP_CONNECT, d0, d1, 0, 0);

    // Wait for connection (with timeout ��� blocking recv like init.rs Phase 19).
    let mut connected = false;
    if let Some(m) = syscall::recv_msg_timeout(sess.reply_port, 5_000_000) {
        if m.tag == NET_TCP_CONNECTED {
            sess.conn_id = m.data[0];
            sess.connected = true;
            connected = true;
            syscall::debug_puts(b"  [iscsi_srv] TCP connected, conn_id=");
            print_num(sess.conn_id);
            syscall::debug_puts(b"\n");
        } else {
            syscall::debug_puts(b"  [iscsi_srv] TCP connect rejected\n");
        }
    }
    if !connected {
        syscall::debug_puts(b"  [iscsi_srv] TCP connect FAILED (timeout)\n");
        loop { syscall::yield_now(); }
    }

    // Perform iSCSI login.
    if !iscsi_login(&mut sess) {
        syscall::debug_puts(b"  [iscsi_srv] login FAILED\n");
        loop { syscall::yield_now(); }
    }

    // Issue TEST UNIT READY.
    if !test_unit_ready(&mut sess) {
        syscall::debug_puts(b"  [iscsi_srv] TUR failed (retrying)\n");
        // Some targets need a moment. Try again.
        syscall::sleep_ms(100);
        test_unit_ready(&mut sess);
    }

    // Read capacity.
    if !read_capacity(&mut sess) {
        syscall::debug_puts(b"  [iscsi_srv] capacity query failed\n");
        loop { syscall::yield_now(); }
    }

    // Register with name server.
    let port = syscall::port_create();
    syscall::ns_register(b"iscsi", port);
    syscall::debug_puts(b"  [iscsi_srv] ready, serving block device\n");

    // Main service loop.
    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => continue,
        };

        match msg.tag {
            IO_CONNECT => {
                let reply_port = msg.data[2] >> 32;
                let capacity = (sess.capacity_blocks as u64) * (sess.block_size as u64);
                syscall::send(reply_port, IO_CONNECT_OK, 0, capacity, 0, 0);
            }
            IO_READ => handle_io_read(&mut sess, &msg),
            IO_WRITE => handle_io_write(&mut sess, &msg),
            IO_STAT => {
                let reply_port = msg.data[0] >> 32;
                let capacity = (sess.capacity_blocks as u64) * (sess.block_size as u64);
                syscall::send(reply_port, IO_STAT_OK, capacity, 0, 0, 0);
            }
            IO_CLOSE => {
                // Could send SCSI logout here.
                let reply_port = msg.data[2] >> 32;
                syscall::send(reply_port, IO_CONNECT_OK, 0, 0, 0, 0);
            }
            _ => {}
        }
    }
}
