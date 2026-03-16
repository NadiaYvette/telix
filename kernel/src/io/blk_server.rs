//! Block device server — wraps a virtio-blk device in the I/O message protocol.

use crate::drivers::virtio_blk::VirtioBlk;
use crate::drivers::virtio_mmio;
use crate::ipc::port::{self, PortId};
use crate::ipc::Message;
use super::protocol::*;
use core::sync::atomic::{AtomicU32, Ordering};

/// Global port ID for the block device server.
pub static BLK_PORT: AtomicU32 = AtomicU32::new(u32::MAX);

/// Block device server entry point.
/// Only runs on AArch64 and RISC-V (x86-64 needs PCI, deferred).
pub fn blk_server() -> ! {
    crate::println!("  [blk] scanning for virtio-blk device...");

    let base = match virtio_mmio::find_device(virtio_mmio::DEVICE_BLK) {
        Some(b) => b,
        None => {
            crate::println!("  [blk] no virtio-blk device found");
            loop { core::hint::spin_loop(); }
        }
    };

    crate::println!("  [blk] found virtio-blk at {:#x}", base);
    let mut dev = match VirtioBlk::init(base) {
        Some(d) => d,
        None => {
            crate::println!("  [blk] failed to init virtio-blk");
            loop { core::hint::spin_loop(); }
        }
    };
    crate::println!("  [blk] virtio-blk ready: {} sectors ({} KiB)",
        dev.capacity, dev.capacity / 2);

    let port = port::create().expect("blk port");
    BLK_PORT.store(port, Ordering::Release);
    crate::println!("  [blk] server ready on port {}", port);

    // Server loop.
    loop {
        let msg = match port::recv(port) {
            Ok(m) => m,
            Err(()) => break,
        };

        match msg.tag {
            IO_READ => {
                let sector = msg.data[1] / 512; // Convert byte offset to sector.
                let reply_port = msg.data[3] as u32;
                let mut buf = [0u8; 512];

                match dev.read_sector(sector, &mut buf) {
                    Ok(()) => {
                        // Return first 40 bytes inline.
                        let packed = pack_inline_data(&buf[..MAX_INLINE_READ]);
                        let reply = Message::new(IO_READ_OK, [
                            512u64,
                            packed[0], packed[1], packed[2], packed[3], packed[4],
                        ]);
                        let _ = port::send_nb(reply_port, reply);
                    }
                    Err(()) => {
                        let reply = Message::new(IO_ERROR, [ERR_IO, 0, 0, 0, 0, 0]);
                        let _ = port::send_nb(reply_port, reply);
                    }
                }
            }

            IO_WRITE => {
                // Phase 3: minimal write support — write first sector from inline data.
                let sector = msg.data[1] / 512;
                let reply_port = msg.data[3] as u32;
                let mut buf = [0u8; 512];
                // For now, just write zeros.
                match dev.write_sector(sector, &buf) {
                    Ok(()) => {
                        let reply = Message::new(IO_WRITE_OK, [512, 0, 0, 0, 0, 0]);
                        let _ = port::send_nb(reply_port, reply);
                    }
                    Err(()) => {
                        let reply = Message::new(IO_ERROR, [ERR_IO, 0, 0, 0, 0, 0]);
                        let _ = port::send_nb(reply_port, reply);
                    }
                }
            }

            _ => {}
        }
    }

    loop { core::hint::spin_loop(); }
}
