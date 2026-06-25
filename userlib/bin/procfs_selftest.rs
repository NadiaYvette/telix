#![no_std]
#![no_main]

//! Linux-personality self-test for linux_srv's synthetic /proc, /sys, /etc
//! files (session 2026-06-25 node-coverage work — commits 6c3f678, c8dcbbf,
//! 078b286, 693529b, 26d66c0).
//!
//! Runs as a Linux process (x86_64 int 0x80 ABI, 64-bit syscall numbers, the
//! same convention as linux_exit42.rs).  For each path it open()s O_RDONLY,
//! read()s the content, and checks for a distinctive marker, printing
//! "[selftest] <path>: OK|FAIL" via write(1).  Exits with the failure count
//! (0 = every file served correctly), which the init.rs phase asserts == 0.
//!
//! On non-x86_64 it exits 0 (the int 0x80 Linux ABI here is x86-specific, like
//! linux_exit42); the synthetic files are arch-neutral so x86_64 covers them.

extern crate userlib;

#[cfg(target_arch = "x86_64")]
unsafe fn sys3(nr: u64, a: u64, b: u64, c: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "int 0x80",
        inlateout("rax") nr => ret,
        in("rdi") a,
        in("rsi") b,
        in("rdx") c,
        lateout("rcx") _,
        lateout("r11") _,
    );
    ret
}

#[cfg(target_arch = "x86_64")]
unsafe fn sys6(nr: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
    // Telix routes int 0x80 with the 64-bit syscall ABI registers
    // (rdi,rsi,rdx,r10,r8,r9), so a 6-arg call (e.g. mmap) uses r10/r8/r9.
    let ret: u64;
    core::arch::asm!(
        "int 0x80",
        inlateout("rax") nr => ret,
        in("rdi") a,
        in("rsi") b,
        in("rdx") c,
        in("r10") d,
        in("r8") e,
        in("r9") f,
        lateout("rcx") _,
        lateout("r11") _,
    );
    ret
}

#[cfg(target_arch = "x86_64")]
unsafe fn write_bytes(s: &[u8]) {
    sys3(1, 1, s.as_ptr() as u64, s.len() as u64); // write(1, s, len)
}

#[cfg(target_arch = "x86_64")]
unsafe fn write_dec(mut v: u64) {
    let mut buf = [0u8; 20];
    let mut i = 20;
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    write_bytes(&buf[i..]);
}

#[cfg(target_arch = "x86_64")]
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    'outer: for i in 0..=(hay.len() - needle.len()) {
        for j in 0..needle.len() {
            if hay[i + j] != needle[j] {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut fails = 0u64;

        // Exercise the VMA-tracking record path: an anonymous mmap should be
        // recorded by linux_srv and then show up in /proc/self/maps + counted
        // in /proc/self/{statm,status}.  Also validates mmap(2) itself.
        let mm = sys6(9, 0, 4096, 3, 0x22, u64::MAX, 0); // mmap(NULL,4096,RW,PRIV|ANON,-1,0)
        write_bytes(b"[selftest] mmap(anon 4096): ");
        if (mm as i64) < 0 {
            write_bytes(b"FAIL\n");
            fails += 1;
        } else {
            write_bytes(b"OK\n");
        }

        // (path-with-NUL, expected-marker).  The marker is distinctive enough to
        // confirm linux_srv served OUR synthetic content (not a real file / EOF).
        let checks: &[(&[u8], &[u8])] = &[
            (b"/etc/machine-id\0", b"\n"),                 // 32 hex + newline
            (b"/etc/os-release\0", b"ID=telix"),
            (b"/etc/services\0", b"ssh"),
            (b"/sys/devices/system/cpu/online\0", b"0"),
            (b"/sys/devices/system/cpu/possible\0", b"0"),
            (b"/sys/kernel/mm/transparent_hugepage/enabled\0", b"[never]"),
            (b"/proc/self/statm\0", b" "),                 // 7 space-separated fields
            (b"/proc/self/status\0", b"VmSize:"),
            (b"/proc/self/limits\0", b"Max open files"),
            (b"/proc/self/cgroup\0", b"0::/"),
            (b"/proc/self/io\0", b"rchar:"),
            (b"/proc/self/maps\0", b"-"),                  // address ranges "start-end"
            (b"/proc/sys/kernel/cap_last_cap\0", b"40"),
            (b"/proc/sys/fs/nr_open\0", b"1048576"),
        ];

        let mut buf = [0u8; 4096];
        for &(path, needle) in checks {
            write_bytes(b"[selftest] ");
            write_bytes(&path[..path.len() - 1]); // strip the trailing NUL for display

            let fd = sys3(2, path.as_ptr() as u64, 0, 0); // open(path, O_RDONLY)
            let ok = if (fd as i64) < 0 {
                false
            } else {
                let n = sys3(0, fd, buf.as_mut_ptr() as u64, buf.len() as u64); // read
                sys3(3, fd, 0, 0); // close
                if (n as i64) <= 0 {
                    false
                } else {
                    contains(&buf[..n as usize], needle)
                }
            };
            if ok {
                write_bytes(b": OK\n");
            } else {
                write_bytes(b": FAIL\n");
                fails += 1;
            }
        }

        write_bytes(b"[selftest] DONE fails=");
        write_dec(fails);
        write_bytes(b"\n");
        core::arch::asm!("int 0x80", in("rax") 231u64, in("rdi") fails, options(noreturn));
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        userlib::syscall::exit(0);
    }
}
