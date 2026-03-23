#![no_std]
#![no_main]

//! Unix domain socket server — manages AF_UNIX sockets.
//!
//! Supports SOCK_STREAM connections with named binding, accept/connect,
//! bidirectional data transfer, and peer credentials (SCM_CREDENTIALS).
//!
//! Protocol tags (0x8000-0x8FFF):
//!   UDS_SOCKET(0x8000)  — create socket, d0=type (0=STREAM)
//!   UDS_BIND(0x8010)    — bind name, d0=handle, d1/d3=name, d2=name_len|reply
//!   UDS_LISTEN(0x8020)  — mark listening, d0=handle
//!   UDS_CONNECT(0x8030) — connect by name, d0/d1=name, d2=name_len|reply, d3/d4/d5=pid/uid/gid
//!   UDS_ACCEPT(0x8040)  — accept connection, d0=handle
//!   UDS_SEND(0x8050)    — send data, d0=handle, d1=w0, d3=w1, d2=len|reply
//!   UDS_RECV(0x8060)    — recv data, d0=handle
//!   UDS_CLOSE(0x8070)   — close socket, d0=handle
//!   UDS_GETPEERCRED(0x8080) — get peer creds, d0=handle

extern crate userlib;

use userlib::syscall;

// Protocol tags.
const UDS_SOCKET: u64 = 0x8000;
const UDS_BIND: u64 = 0x8010;
const UDS_LISTEN: u64 = 0x8020;
const UDS_CONNECT: u64 = 0x8030;
const UDS_ACCEPT: u64 = 0x8040;
const UDS_SEND: u64 = 0x8050;
const UDS_RECV: u64 = 0x8060;
const UDS_CLOSE: u64 = 0x8070;
const UDS_GETPEERCRED: u64 = 0x8080;

const UDS_OK: u64 = 0x8100;
const UDS_EOF: u64 = 0x81FF;
const UDS_ERROR: u64 = 0x8F00;

// Limits.
const MAX_SOCKETS: usize = 32;
const MAX_PENDING: usize = 4;
const RX_BUF_SIZE: usize = 256;
const MAX_NAME: usize = 16;

#[derive(Clone, Copy, PartialEq)]
enum SockState {
    Free,
    Created,
    Bound,
    Listening,
    Connected,
    Closed,
}

struct UnixSocket {
    state: SockState,
    sock_type: u8, // 0 = STREAM
    name: [u8; MAX_NAME],
    name_len: usize,
    peer: u32, // index of connected peer (u32::MAX = none)
    // Credentials of the connecting client (stored on peer's socket).
    cred_pid: u32,
    cred_uid: u32,
    cred_gid: u32,
    // Accept queue (for listening sockets).
    pending: [u32; MAX_PENDING],       // server-end socket indices
    pending_count: usize,
    // Blocked accept caller.
    accept_reply: u32, // reply port (0 = none blocked)
    // Receive buffer (ring buffer).
    rx_buf: [u8; RX_BUF_SIZE],
    rx_head: usize,
    rx_tail: usize,
    rx_eof: bool,
    // Blocked recv caller.
    recv_reply: u32, // reply port (0 = none blocked)
}

impl UnixSocket {
    const fn empty() -> Self {
        Self {
            state: SockState::Free,
            sock_type: 0,
            name: [0; MAX_NAME],
            name_len: 0,
            peer: u32::MAX,
            cred_pid: 0,
            cred_uid: 0,
            cred_gid: 0,
            pending: [0; MAX_PENDING],
            pending_count: 0,
            accept_reply: 0,
            rx_buf: [0; RX_BUF_SIZE],
            rx_head: 0,
            rx_tail: 0,
            rx_eof: false,
            recv_reply: 0,
        }
    }

    fn rx_len(&self) -> usize {
        if self.rx_head >= self.rx_tail {
            self.rx_head - self.rx_tail
        } else {
            RX_BUF_SIZE - self.rx_tail + self.rx_head
        }
    }

    fn rx_free(&self) -> usize {
        RX_BUF_SIZE - 1 - self.rx_len()
    }

    fn rx_push(&mut self, data: &[u8]) -> usize {
        let mut written = 0;
        for &b in data {
            if self.rx_free() == 0 {
                break;
            }
            self.rx_buf[self.rx_head] = b;
            self.rx_head = (self.rx_head + 1) % RX_BUF_SIZE;
            written += 1;
        }
        written
    }

    fn rx_pop(&mut self, out: &mut [u8]) -> usize {
        let mut read = 0;
        while read < out.len() && self.rx_len() > 0 {
            out[read] = self.rx_buf[self.rx_tail];
            self.rx_tail = (self.rx_tail + 1) % RX_BUF_SIZE;
            read += 1;
        }
        read
    }
}

static mut SOCKS: [UnixSocket; MAX_SOCKETS] = [const { UnixSocket::empty() }; MAX_SOCKETS];

fn alloc_socket() -> Option<u32> {
    unsafe {
        for i in 0..MAX_SOCKETS {
            if SOCKS[i].state == SockState::Free {
                SOCKS[i] = UnixSocket::empty();
                SOCKS[i].state = SockState::Created;
                return Some(i as u32);
            }
        }
    }
    None
}

fn unpack_name(d0: u64, d1: u64, len: usize) -> ([u8; MAX_NAME], usize) {
    let mut buf = [0u8; MAX_NAME];
    let n = if len < MAX_NAME { len } else { MAX_NAME };
    let b0 = d0.to_le_bytes();
    let b1 = d1.to_le_bytes();
    let mut i = 0;
    while i < n && i < 8 {
        buf[i] = b0[i];
        i += 1;
    }
    while i < n && i < 16 {
        buf[i] = b1[i - 8];
        i += 1;
    }
    (buf, n)
}

/// Find a listening socket by name.
fn find_listening(name: &[u8], name_len: usize) -> Option<u32> {
    unsafe {
        for i in 0..MAX_SOCKETS {
            if SOCKS[i].state == SockState::Listening
                && SOCKS[i].name_len == name_len
            {
                let mut ok = true;
                for j in 0..name_len {
                    if SOCKS[i].name[j] != name[j] {
                        ok = false;
                        break;
                    }
                }
                if ok {
                    return Some(i as u32);
                }
            }
        }
    }
    None
}

/// Pack up to 16 bytes into two u64 words.
fn pack_bytes(data: &[u8], len: usize) -> (u64, u64) {
    let mut w0 = 0u64;
    let mut w1 = 0u64;
    let n = if len < 16 { len } else { 16 };
    for i in 0..n {
        if i < 8 {
            w0 |= (data[i] as u64) << (i * 8);
        } else {
            w1 |= (data[i] as u64) << ((i - 8) * 8);
        }
    }
    (w0, w1)
}

/// Send a reply with up to 4 data words.
fn reply(port: u32, tag: u64, d0: u64, d1: u64, d2: u64, d3: u64) {
    syscall::send(port, tag, d0, d1, d2, d3);
}

/// Deliver data (or EOF) to a socket that has a blocked recv.
/// Returns true if data was delivered to a waiter.
fn try_wake_recv(sock_idx: u32) {
    let s = unsafe { &mut SOCKS[sock_idx as usize] };
    if s.recv_reply == 0 {
        return;
    }
    let rp = s.recv_reply;
    // Check if there's data.
    if s.rx_len() > 0 {
        let mut tmp = [0u8; 16];
        let n = s.rx_pop(&mut tmp);
        let (w0, w1) = pack_bytes(&tmp, n);
        s.recv_reply = 0;
        reply(rp, UDS_OK, w0, w1, n as u64, 0);
    } else if s.rx_eof {
        s.recv_reply = 0;
        reply(rp, UDS_EOF, 0, 0, 0, 0);
    }
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    let svc_port = syscall::port_create() as u32;
    syscall::ns_register(b"uds", svc_port);

    loop {
        let msg = match syscall::recv_msg(svc_port) {
            Some(m) => m,
            None => continue,
        };

        let tag = msg.tag;
        let reply_port = (msg.data[2] >> 32) as u32;

        match tag {
            UDS_SOCKET => {
                let sock_type = msg.data[0] as u8;
                if let Some(h) = alloc_socket() {
                    unsafe { SOCKS[h as usize].sock_type = sock_type; }
                    reply(reply_port, UDS_OK, h as u64, 0, 0, 0);
                } else {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                }
            }

            UDS_BIND => {
                let handle = msg.data[0] as u32;
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let (name, nlen) = unpack_name(msg.data[1], msg.data[3], name_len);
                if handle as usize >= MAX_SOCKETS {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }
                let s = unsafe { &mut SOCKS[handle as usize] };
                if s.state != SockState::Created {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }
                s.name = name;
                s.name_len = nlen;
                s.state = SockState::Bound;
                reply(reply_port, UDS_OK, 0, 0, 0, 0);
            }

            UDS_LISTEN => {
                let handle = msg.data[0] as u32;
                if handle as usize >= MAX_SOCKETS {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }
                let s = unsafe { &mut SOCKS[handle as usize] };
                if s.state != SockState::Bound {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }
                s.state = SockState::Listening;
                reply(reply_port, UDS_OK, 0, 0, 0, 0);
            }

            UDS_CONNECT => {
                // d0/d1 = name, d2 low16 = name_len, d3 = pid|(uid<<32)
                let name_len = (msg.data[2] & 0xFFFF) as usize;
                let (name, nlen) = unpack_name(msg.data[0], msg.data[1], name_len);
                let pid = msg.data[3] as u32;
                let uid = (msg.data[3] >> 32) as u32;
                let gid = 0u32; // gid not packed (would need d4, unavailable in 4-word send)

                // Find listening socket.
                let listener = match find_listening(&name, nlen) {
                    Some(l) => l,
                    None => {
                        reply(reply_port, UDS_ERROR, 1, 0, 0, 0); // ECONNREFUSED
                        continue;
                    }
                };

                // Allocate server-end and client-end sockets.
                let srv_end = match alloc_socket() {
                    Some(h) => h,
                    None => {
                        reply(reply_port, UDS_ERROR, 2, 0, 0, 0);
                        continue;
                    }
                };
                let cli_end = match alloc_socket() {
                    Some(h) => h,
                    None => {
                        unsafe { SOCKS[srv_end as usize].state = SockState::Free; }
                        reply(reply_port, UDS_ERROR, 2, 0, 0, 0);
                        continue;
                    }
                };

                // Link them as peers.
                unsafe {
                    SOCKS[srv_end as usize].state = SockState::Connected;
                    SOCKS[srv_end as usize].peer = cli_end;
                    // Store connector's credentials on server-end (so acceptor can query).
                    SOCKS[srv_end as usize].cred_pid = pid;
                    SOCKS[srv_end as usize].cred_uid = uid;
                    SOCKS[srv_end as usize].cred_gid = gid;

                    SOCKS[cli_end as usize].state = SockState::Connected;
                    SOCKS[cli_end as usize].peer = srv_end;
                    // Client-end credentials: set to same (peer creds from acceptor side).
                    SOCKS[cli_end as usize].cred_pid = pid;
                    SOCKS[cli_end as usize].cred_uid = uid;
                    SOCKS[cli_end as usize].cred_gid = gid;
                }

                // Check if accept() is already blocked on the listener.
                let accept_rp = unsafe { SOCKS[listener as usize].accept_reply };
                if accept_rp != 0 {
                    // Wake the blocked acceptor immediately.
                    unsafe { SOCKS[listener as usize].accept_reply = 0; }
                    reply(accept_rp, UDS_OK, srv_end as u64, 0, 0, 0);
                } else {
                    // Queue server-end for later accept().
                    let ls = unsafe { &mut SOCKS[listener as usize] };
                    if ls.pending_count < MAX_PENDING {
                        ls.pending[ls.pending_count] = srv_end;
                        ls.pending_count += 1;
                    } else {
                        // Queue full — reject.
                        unsafe {
                            SOCKS[srv_end as usize].state = SockState::Free;
                            SOCKS[cli_end as usize].state = SockState::Free;
                        }
                        reply(reply_port, UDS_ERROR, 3, 0, 0, 0); // ECONNREFUSED
                        continue;
                    }
                }

                // Reply to connector with client-end handle.
                reply(reply_port, UDS_OK, cli_end as u64, 0, 0, 0);
            }

            UDS_ACCEPT => {
                let handle = msg.data[0] as u32;
                if handle as usize >= MAX_SOCKETS {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }
                let s = unsafe { &mut SOCKS[handle as usize] };
                if s.state != SockState::Listening {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }

                if s.pending_count > 0 {
                    // Dequeue first pending connection.
                    let srv_end = s.pending[0];
                    // Shift queue.
                    let mut i = 0;
                    while i + 1 < s.pending_count {
                        s.pending[i] = s.pending[i + 1];
                        i += 1;
                    }
                    s.pending_count -= 1;
                    reply(reply_port, UDS_OK, srv_end as u64, 0, 0, 0);
                } else {
                    // No pending — block the acceptor.
                    s.accept_reply = reply_port;
                }
            }

            UDS_SEND => {
                let handle = msg.data[0] as u32;
                let len = (msg.data[2] & 0xFFFF) as usize;
                let len = if len > 16 { 16 } else { len };
                if handle as usize >= MAX_SOCKETS {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }
                let s = unsafe { &SOCKS[handle as usize] };
                if s.state != SockState::Connected {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }
                let peer_idx = s.peer;
                if peer_idx == u32::MAX || peer_idx as usize >= MAX_SOCKETS {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }

                // Unpack data bytes.
                let mut tmp = [0u8; 16];
                let b0 = msg.data[1].to_le_bytes();
                let b1 = msg.data[3].to_le_bytes();
                let mut i = 0;
                while i < len && i < 8 {
                    tmp[i] = b0[i];
                    i += 1;
                }
                while i < len && i < 16 {
                    tmp[i] = b1[i - 8];
                    i += 1;
                }

                // Push into peer's rx_buf.
                let peer = unsafe { &mut SOCKS[peer_idx as usize] };
                if peer.state == SockState::Closed || peer.state == SockState::Free {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }
                let written = peer.rx_push(&tmp[..len]);
                reply(reply_port, UDS_OK, written as u64, 0, 0, 0);

                // Wake blocked recv on peer if any.
                try_wake_recv(peer_idx);
            }

            UDS_RECV => {
                let handle = msg.data[0] as u32;
                if handle as usize >= MAX_SOCKETS {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }
                let s = unsafe { &mut SOCKS[handle as usize] };
                if s.state != SockState::Connected && s.state != SockState::Closed {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }

                if s.rx_len() > 0 {
                    let mut tmp = [0u8; 16];
                    let n = s.rx_pop(&mut tmp);
                    let (w0, w1) = pack_bytes(&tmp, n);
                    reply(reply_port, UDS_OK, w0, w1, n as u64, 0);
                } else if s.rx_eof {
                    reply(reply_port, UDS_EOF, 0, 0, 0, 0);
                } else {
                    // Block — store reply port.
                    s.recv_reply = reply_port;
                }
            }

            UDS_CLOSE => {
                let handle = msg.data[0] as u32;
                if handle as usize >= MAX_SOCKETS {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }
                let s = unsafe { &mut SOCKS[handle as usize] };
                let peer_idx = s.peer;
                s.state = SockState::Free;
                s.peer = u32::MAX;

                // Signal EOF to peer.
                if peer_idx != u32::MAX && (peer_idx as usize) < MAX_SOCKETS {
                    let peer = unsafe { &mut SOCKS[peer_idx as usize] };
                    if peer.state == SockState::Connected {
                        peer.rx_eof = true;
                        // Wake blocked recv on peer.
                        try_wake_recv(peer_idx);
                    }
                }

                reply(reply_port, UDS_OK, 0, 0, 0, 0);
            }

            UDS_GETPEERCRED => {
                let handle = msg.data[0] as u32;
                if handle as usize >= MAX_SOCKETS {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }
                let s = unsafe { &SOCKS[handle as usize] };
                if s.state != SockState::Connected {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }
                // Return credentials of the peer.
                let peer_idx = s.peer;
                if peer_idx == u32::MAX || peer_idx as usize >= MAX_SOCKETS {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                    continue;
                }
                let peer = unsafe { &SOCKS[peer_idx as usize] };
                reply(
                    reply_port,
                    UDS_OK,
                    peer.cred_pid as u64,
                    (peer.cred_uid as u64) | ((peer.cred_gid as u64) << 32),
                    0,
                    0,
                );
            }

            _ => {
                if reply_port != 0 {
                    reply(reply_port, UDS_ERROR, 0, 0, 0, 0);
                }
            }
        }
    }
}
