#![no_std]
#![no_main]

//! Minimal test binary for Linux personality execve.
//! Writes a message via Linux write(1, ...) and exits with code 42.
//! Uses Linux ABI (int 0x80 on x86_64) — designed to run under the
//! Linux personality server.

extern crate userlib;

#[unsafe(no_mangle)]
fn main(_arg0: u64, _arg1: u64, _arg2: u64) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let msg = b"[linux_exit42] hello from execve!\n";
        let _: u64;
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") 1u64 => _,
            in("rdi") 1u64,
            in("rsi") msg.as_ptr() as u64,
            in("rdx") msg.len() as u64,
            lateout("rcx") _,
            lateout("r11") _,
        );
        core::arch::asm!("int 0x80", in("rax") 231u64, in("rdi") 42u64, options(noreturn));
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        userlib::syscall::exit(42);
    }
}
