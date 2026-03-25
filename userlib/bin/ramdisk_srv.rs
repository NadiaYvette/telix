#![no_std]
#![no_main]

extern crate userlib;

use userlib::syscall;

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

const ERR_INVALID: u64 = 3;

const MAX_INLINE_READ: usize = 40;
const RAMDISK_SIZE: usize = 16384; // 4 pages

use core::cell::UnsafeCell;

#[repr(transparent)]
struct RamdiskBuf(UnsafeCell<[u8; RAMDISK_SIZE]>);
unsafe impl Sync for RamdiskBuf {}

static RAMDISK: RamdiskBuf = RamdiskBuf(UnsafeCell::new([0; RAMDISK_SIZE]));

fn pack_inline_data(data: &[u8]) -> [u64; 5] {
    let mut words = [0u64; 5];
    for (i, &b) in data.iter().enumerate().take(MAX_INLINE_READ) {
        words[i / 8] |= (b as u64) << ((i % 8) * 8);
    }
    words
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

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    let port = syscall::port_create();
    let my_aspace = syscall::aspace_id();

    // Register with name server.
    syscall::ns_register(b"ramdisk", port);

    syscall::debug_puts(b"  [ramdisk_srv] ready on port ");
    print_num(port as u64);
    syscall::debug_puts(b"\n");

    loop {
        let msg = match syscall::recv_msg(port) {
            Some(m) => m,
            None => break,
        };

        match msg.tag {
            IO_CONNECT => {
                let reply_port = msg.data[2] >> 32;
                // data[0]=handle(0), data[1]=size, data[2]=server_aspace_id
                syscall::send(reply_port, IO_CONNECT_OK,
                    0, RAMDISK_SIZE as u64, my_aspace as u64, 0);
            }

            IO_READ => {
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let grant_va = msg.data[3] as usize;

                if offset >= RAMDISK_SIZE {
                    syscall::send_nb(reply_port, IO_ERROR, ERR_INVALID, 0);
                    continue;
                }

                let end = (offset + length).min(RAMDISK_SIZE);
                let data = unsafe {
                    let ptr = (RAMDISK.0.get() as *const u8).add(offset);
                    core::slice::from_raw_parts(ptr, end - offset)
                };

                if grant_va != 0 {
                    // Grant-based read.
                    let dst = grant_va as *mut u8;
                    unsafe {
                        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
                    }
                    syscall::send_nb(reply_port, IO_READ_OK, data.len() as u64, 0);
                } else {
                    // Inline read.
                    let bytes_read = data.len().min(MAX_INLINE_READ);
                    let packed = pack_inline_data(&data[..bytes_read]);
                    syscall::send(reply_port, IO_READ_OK,
                        bytes_read as u64, packed[0], packed[1], packed[2]);
                }
            }

            IO_WRITE => {
                let offset = msg.data[1] as usize;
                let length = (msg.data[2] & 0xFFFF_FFFF) as usize;
                let reply_port = msg.data[2] >> 32;
                let grant_va = msg.data[3] as usize;

                if offset >= RAMDISK_SIZE {
                    syscall::send_nb(reply_port, IO_ERROR, ERR_INVALID, 0);
                    continue;
                }

                let end = (offset + length).min(RAMDISK_SIZE);
                let actual_len = end - offset;

                if grant_va != 0 && actual_len > 8 {
                    // Grant-based write: copy from granted pages into ramdisk.
                    let src = grant_va as *const u8;
                    unsafe {
                        let dst: *mut u8 = (RAMDISK.0.get() as *mut u8).add(offset);
                        core::ptr::copy_nonoverlapping(src, dst, actual_len);
                    }
                } else {
                    // Inline write: data[3] carries up to 8 bytes of packed data.
                    let src_word = msg.data[3] as u64;
                    let write_len = actual_len.min(8);
                    for i in 0..write_len {
                        unsafe {
                            let ptr = (RAMDISK.0.get() as *mut u8).add(offset + i);
                            ptr.write((src_word >> (i * 8)) as u8);
                        }
                    }
                }

                syscall::send_nb(reply_port, IO_WRITE_OK, actual_len as u64, 0);
            }

            IO_STAT => {
                let reply_port = msg.data[0] >> 32;
                syscall::send_nb(reply_port, IO_STAT_OK, RAMDISK_SIZE as u64, 0);
            }

            IO_CLOSE => {}
            _ => {}
        }
    }

    loop { core::hint::spin_loop(); }
}
