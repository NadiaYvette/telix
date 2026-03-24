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
    my_port: u32,
    reply_port: u32,
    net_port: u32,
    my_node_id: u16,
    nodes: [NodeEntry; MAX_NODES],
    // Pending accept: true if we're waiting for incoming connections.
    accepting: bool,
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

fn serialize_frame(buf: &mut [u8; WIRE_FRAME_SIZE], target_port: u32, tag: u64, data: &[u64; 4], src_node: u16) {
    // Bytes 0-3: magic
    buf[0..4].copy_from_slice(&WIRE_MAGIC.to_le_bytes());
    // Bytes 4-7: target_port (with node=0 for local delivery on remote side)
    let local_port = target_port & 0xFFFF; // strip node, deliver locally on remote
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
    // Bytes 50-63: padding
    buf[50..64].fill(0);
}

fn deserialize_frame(buf: &[u8; WIRE_FRAME_SIZE]) -> Option<(u32, u64, [u64; 4], u16)> {
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != WIRE_MAGIC {
        return None;
    }
    let target_port = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let tag = u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]);
    let mut data = [0u64; 4];
    for i in 0..4 {
        let off = 16 + i * 8;
        data[i] = u64::from_le_bytes([
            buf[off], buf[off+1], buf[off+2], buf[off+3],
            buf[off+4], buf[off+5], buf[off+6], buf[off+7],
        ]);
    }
    let src_node = u16::from_le_bytes([buf[48], buf[49]]);
    Some((target_port, tag, data, src_node))
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
        self.nodes.iter().position(|n| n.active && n.node_id == node_id)
    }

    fn find_node_by_conn(&self, conn_id: usize) -> Option<usize> {
        self.nodes.iter().position(|n| n.active && n.conn_id == conn_id)
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
                    if reply.tag == NET_TCP_SEND_OK || reply.tag == NET_TCP_FAIL || reply.tag == NET_TCP_CLOSED {
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
        let port = self.nodes[node_idx].tcp_port as u32;
        let d1 = (port as u64) | ((self.reply_port as u64) << 32);
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
        let target_port = (msg.tag >> 32) as u32;
        let node_id = (target_port >> 16) as u16;
        let original_tag = msg.data[0];
        let original_data = [msg.data[1], msg.data[2], msg.data[3], msg.data[4]];

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
        serialize_frame(&mut frame, target_port, original_tag, &original_data, self.my_node_id);
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

            if let Some((target_port, tag, data, _src_node)) = deserialize_frame(&frame) {
                // Deliver locally.
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
                        self.handle_inbound_data(conn_id, len, reply.data[1], reply.data[2], reply.data[3]);
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
        let reply_port = (msg.data[2] >> 32) as u32;

        // Find a free slot or existing entry for this node_id.
        let slot = self.find_node_by_id(node_id).unwrap_or_else(|| {
            self.nodes.iter().position(|n| !n.active).unwrap_or(MAX_NODES)
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
        if self.accepting { return; }
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
    let my_port = syscall::port_create() as u32;
    let reply_port = syscall::port_create() as u32;

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
    print_num(my_port as u64);
    syscall::debug_puts(b"\n");

    // Bind + listen on LISTEN_TCP_PORT for incoming proxy connections.
    let d1_bind = (LISTEN_TCP_PORT as u64) | ((reply_port as u64) << 32);
    syscall::send(net_port, NET_TCP_BIND, LISTEN_TCP_PORT as u64, d1_bind, 0, 0);
    // Wait for bind reply.
    if let Some(reply) = syscall::recv_msg(reply_port) {
        if reply.tag == NET_TCP_BIND_OK {
            let d2_listen = ((reply_port as u64) << 32);
            syscall::send(net_port, NET_TCP_LISTEN, LISTEN_TCP_PORT as u64, 1, d2_listen, 0);
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
            let tag_lo = msg.tag & 0xFFFF_FFFF;

            if tag_lo == PROXY_MARKER_LO && from_port == my_port {
                // Outbound: kernel-redirected non-local send.
                srv.handle_outbound(&msg);
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
                        srv.handle_inbound_data(srv.nodes[i].conn_id, len, msg.data[1], msg.data[2], msg.data[3]);
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
