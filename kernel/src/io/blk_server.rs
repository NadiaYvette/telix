//! Block device server — wraps a virtio-blk device in the I/O message protocol.

use crate::drivers::virtio_blk::VirtioBlk;
use crate::drivers::virtio_mmio;
use crate::ipc::port::{self};
use crate::ipc::Message;
use super::protocol::*;
use core::sync::atomic::{AtomicU64, Ordering};

/// Global port ID for the block device server.
pub static BLK_PORT: AtomicU64 = AtomicU64::new(u64::MAX);

/// Ensure the kernel page table is active (for accessing grant VAs).
/// On AArch64, kernel threads may run with a user process's page table
/// still in TTBR0. Grant mappings live in the kernel boot page table.
fn ensure_kernel_pt() {
    let kern_root = crate::mm::hat::boot_page_table_root();
    crate::mm::hat::switch_page_table(kern_root);
    // RISC-V: Grant pages have PTE_U set. S-mode must set sstatus.SUM to access them.
    #[cfg(target_arch = "riscv64")]
    unsafe { core::arch::asm!("csrs sstatus, {}", in(reg) 1usize << 18); }
}

/// Stub server when no virtio-blk device is present.
/// Registers with the name server so clients don't hang, then replies
/// with IO_ERROR to all requests.
fn blk_server_no_device() -> ! {
    let port = port::create().expect("blk null port");
    BLK_PORT.store(port, Ordering::Release);

    // Register with name server so ns_lookup("blk") doesn't hang.
    let nsrv = crate::io::namesrv::NAMESRV_PORT.load(Ordering::Acquire);
    if nsrv != u64::MAX {
        let (n0, n1, _) = pack_name(b"blk");
        let reply_port = port::create().expect("blk reg reply");
        let d3 = 3u64 | ((reply_port as u64) << 32);
        let msg = Message::new(NS_REGISTER, [n0, n1, port as u64, d3, 0, 0]);
        let _ = crate::ipc::port::send(nsrv, msg);
        let _ = crate::ipc::port::recv(reply_port);
        crate::ipc::port::destroy(reply_port);
    }

    crate::println!("  [blk] no-device stub on port {}", port);

    // Reply with IO_ERROR to every request.
    loop {
        let msg = match port::recv(port) {
            Ok(m) => m,
            Err(()) => break,
        };
        let reply_port = msg.data[2] >> 32;
        if reply_port != 0 {
            let _ = port::send_nb(reply_port, Message::new(IO_ERROR, [0, 0, 0, 0, 0, 0]));
        }
    }
    loop { core::hint::spin_loop(); }
}

/// Block device server entry point.
/// Only runs on AArch64 and RISC-V (x86-64 needs PCI, deferred).
pub fn blk_server() -> ! {
    crate::println!("  [blk] scanning for virtio-blk device...");

    let base = match virtio_mmio::find_device(virtio_mmio::DEVICE_BLK) {
        Some(b) => b,
        None => {
            crate::println!("  [blk] no virtio-blk device found — serving errors");
            blk_server_no_device();
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
    let capacity = dev.capacity;
    crate::println!("  [blk] virtio-blk ready: {} sectors ({} KiB)",
        capacity, capacity / 2);

    // Enable virtio-blk interrupt for IRQ-driven I/O.
    {
        let irq = virtio_mmio::device_irq(base);
        if irq != 0 {
            crate::arch::irq::enable_device_irq(irq);
        }
    }

    let port = port::create().expect("blk port");
    BLK_PORT.store(port, Ordering::Release);

    // Create an aspace for the blk server so userspace can grant pages to us.
    // Kernel threads have aspace_id=0 which doesn't exist in the aspace table,
    // so we create a real one wrapping the kernel page table.
    let pt_root = crate::mm::hat::boot_page_table_root();
    let my_aspace = crate::mm::aspace::create(pt_root).expect("blk aspace");

    // Register with name server.
    {
        let nsrv = crate::io::namesrv::NAMESRV_PORT.load(Ordering::Acquire);
        if nsrv != u64::MAX {
            let (n0, n1, _n2) = pack_name(b"blk");
            let name_len = 3u64;
            let reply_port = port::create().expect("blk reg reply port");
            let d3 = name_len | ((reply_port as u64) << 32);
            let msg = Message::new(NS_REGISTER, [n0, n1, port as u64, d3, 0, 0]);
            let _ = crate::ipc::port::send(nsrv, msg);
            let _ = crate::ipc::port::recv(reply_port); // wait for NS_REGISTER_OK
            crate::ipc::port::destroy(reply_port);
        }
    }

    crate::println!("  [blk] server ready on port {}", port);

    // Server loop.
    loop {
        let msg = match port::recv(port) {
            Ok(m) => m,
            Err(()) => break,
        };

        match msg.tag {
            IO_CONNECT => {
                // data[0..1] = name, data[2] = name_len | reply_port << 32, data[3] = unused
                let reply_port = msg.data[2] >> 32;
                // Block device: handle=0, size=capacity*512
                let reply = Message::new(IO_CONNECT_OK, [
                    0, // handle (always 0 for single block device)
                    capacity * 512, // total size in bytes
                    my_aspace as u64, // server aspace ID
                    0, 0, 0,
                ]);
                let _ = port::send_nb(reply_port, reply);
            }

            IO_READ => {
                // data[0] = handle, data[1] = byte offset
                // data[2] = length (low 32) | reply_port (high 32)
                // data[3] = grant_dst_va (if grant)
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let grant_va = msg.data[3] as usize;

                let sector = (offset / 512) as u64;
                let mut buf = [0u8; 512];

                match dev.read_sector(sector, &mut buf) {
                    Ok(()) => {
                        let bytes_read = length.min(512);
                        if grant_va != 0 {
                            // Grant-based: copy data into granted pages.
                            ensure_kernel_pt();
                            let dst = grant_va as *mut u8;
                            unsafe {
                                core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, bytes_read);
                            }
                            let reply = Message::new(IO_READ_OK, [bytes_read as u64, 0, 0, 0, 0, 0]);
                            let _ = port::send_nb(reply_port, reply);
                        } else {
                            // Inline read.
                            let inline_len = bytes_read.min(MAX_INLINE_READ);
                            let packed = pack_inline_data(&buf[..inline_len]);
                            let reply = Message::new(IO_READ_OK, [
                                inline_len as u64,
                                packed[0], packed[1], packed[2], packed[3], packed[4],
                            ]);
                            let _ = port::send_nb(reply_port, reply);
                        }
                    }
                    Err(()) => {
                        let reply = Message::new(IO_ERROR, [ERR_IO, 0, 0, 0, 0, 0]);
                        let _ = port::send_nb(reply_port, reply);
                    }
                }
            }

            IO_WRITE => {
                // data[0] = handle, data[1] = byte offset
                // data[2] = length (low 32) | reply_port (high 32)
                // data[3] = grant_src_va (if grant)
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let grant_va = msg.data[3] as usize;

                let sector = (offset / 512) as u64;
                let mut buf = [0u8; 512];

                if grant_va != 0 {
                    // Grant-based write: copy from granted pages.
                    ensure_kernel_pt();
                    let bytes_to_write = length.min(512);
                    let src = grant_va as *const u8;
                    unsafe {
                        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), bytes_to_write);
                    }
                }

                match dev.write_sector(sector, &buf) {
                    Ok(()) => {
                        let reply = Message::new(IO_WRITE_OK, [length.min(512) as u64, 0, 0, 0, 0, 0]);
                        let _ = port::send_nb(reply_port, reply);
                    }
                    Err(()) => {
                        let reply = Message::new(IO_ERROR, [ERR_IO, 0, 0, 0, 0, 0]);
                        let _ = port::send_nb(reply_port, reply);
                    }
                }
            }

            IO_STAT => {
                // data[0] = handle | (reply_port << 32)
                let reply_port = msg.data[0] >> 32;
                let reply = Message::new(IO_STAT_OK, [capacity * 512, 0, 0, 0, 0, 0]);
                let _ = port::send_nb(reply_port, reply);
            }

            IO_CLOSE => {}
            _ => {}
        }
    }

    loop { core::hint::spin_loop(); }
}
