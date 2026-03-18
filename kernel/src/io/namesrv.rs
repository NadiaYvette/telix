//! Name server — maps service names to IPC port IDs.
//!
//! Runs as a kernel thread. Clients register and look up services via IPC messages.

use crate::ipc::{port, Message};
use super::protocol::*;
use core::sync::atomic::{AtomicU32, Ordering};

/// Global port ID for the name server.
pub static NAMESRV_PORT: AtomicU32 = AtomicU32::new(u32::MAX);

const MAX_SERVICES: usize = 16;
const MAX_SVC_NAME: usize = 24;

struct ServiceEntry {
    name: [u8; MAX_SVC_NAME],
    name_len: usize,
    port_id: u32,
    active: bool,
}

impl ServiceEntry {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_SVC_NAME],
            name_len: 0,
            port_id: 0,
            active: false,
        }
    }
}

struct NameTable {
    entries: [ServiceEntry; MAX_SERVICES],
    count: usize,
}

impl NameTable {
    const fn new() -> Self {
        Self {
            entries: [const { ServiceEntry::empty() }; MAX_SERVICES],
            count: 0,
        }
    }

    fn register(&mut self, name: &[u8], port_id: u32) -> bool {
        // Check for duplicate — update if exists.
        for i in 0..self.count {
            if self.entries[i].active && self.entries[i].name_len == name.len()
                && &self.entries[i].name[..name.len()] == name
            {
                self.entries[i].port_id = port_id;
                return true;
            }
        }
        if self.count >= MAX_SERVICES {
            return false;
        }
        let e = &mut self.entries[self.count];
        let len = name.len().min(MAX_SVC_NAME);
        e.name[..len].copy_from_slice(&name[..len]);
        e.name_len = len;
        e.port_id = port_id;
        e.active = true;
        self.count += 1;
        true
    }

    fn lookup(&self, name: &[u8]) -> Option<u32> {
        for i in 0..self.count {
            if self.entries[i].active && self.entries[i].name_len == name.len()
                && &self.entries[i].name[..name.len()] == name
            {
                return Some(self.entries[i].port_id);
            }
        }
        None
    }
}

/// Name server entry point (kernel thread).
pub fn namesrv_server() -> ! {
    let srv_port = port::create().expect("namesrv port");
    NAMESRV_PORT.store(srv_port, Ordering::Release);
    crate::println!("  [namesrv] ready on port {}", srv_port);

    let mut table = NameTable::new();

    loop {
        let msg = match port::recv(srv_port) {
            Ok(m) => m,
            Err(()) => break,
        };

        match msg.tag {
            NS_REGISTER => {
                let name_len = (msg.data[3] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[3] >> 32) as u32;
                let service_port = msg.data[2] as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], 0, name_len);
                let name = &name_buf[..name_len.min(MAX_SVC_NAME)];

                table.register(name, service_port);
                let _ = port::send_nb(reply_port, Message::new(NS_REGISTER_OK, [0, 0, 0, 0, 0, 0]));
            }

            NS_LOOKUP => {
                let name_len = (msg.data[3] & 0xFFFF_FFFF) as usize;
                let reply_port = (msg.data[3] >> 32) as u32;
                let name_buf = unpack_name(msg.data[0], msg.data[1], msg.data[2], name_len);
                let name = &name_buf[..name_len.min(MAX_SVC_NAME)];

                let port_id = table.lookup(name).unwrap_or(u32::MAX);

                // Grant SEND cap for the looked-up service port to the client task.
                if port_id != u32::MAX {
                    if let Some(client_task) = port::port_creator(reply_port) {
                        let mut caps = crate::cap::CAP_SYSTEM.lock();
                        caps.grant_send_cap(client_task, port_id);
                    }
                }

                let _ = port::send_nb(reply_port, Message::new(NS_LOOKUP_OK, [port_id as u64, 0, 0, 0, 0, 0]));
            }

            _ => {}
        }
    }

    loop { core::hint::spin_loop(); }
}
