//! LoongArch64 raw syscall stubs via the syscall instruction.
//!
//! ABI: number in a7 ($r11), args in a0-a5 ($r4-$r9), return in a0 ($r4).
//!
//! NOTE: These stubs are `#[inline(never)]` to work around a LoongArch64
//! codegen issue where inlining the asm block can cause the compiler to use
//! the input value of $r4 (the first argument) instead of re-reading the
//! output after the syscall instruction.

#[inline(never)]
pub unsafe fn syscall0(nr: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall 0",
            in("$r11") nr,
            lateout("$r4") ret,
            lateout("$r5") _,
            lateout("$r6") _,
        );
    }
    ret
}

#[inline(never)]
pub unsafe fn syscall1(nr: u64, a0: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall 0",
            in("$r11") nr,
            inlateout("$r4") a0 => ret,
            lateout("$r5") _,
            lateout("$r6") _,
        );
    }
    ret
}

#[inline(never)]
pub unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall 0",
            in("$r11") nr,
            inlateout("$r4") a0 => ret,
            inlateout("$r5") a1 => _,
            lateout("$r6") _,
        );
    }
    ret
}

#[inline(never)]
pub unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall 0",
            in("$r11") nr,
            inlateout("$r4") a0 => ret,
            inlateout("$r5") a1 => _,
            inlateout("$r6") a2 => _,
        );
    }
    ret
}

#[inline(never)]
pub unsafe fn syscall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall 0",
            in("$r11") nr,
            inlateout("$r4") a0 => ret,
            inlateout("$r5") a1 => _,
            inlateout("$r6") a2 => _,
            inlateout("$r7") a3 => _,
        );
    }
    ret
}

#[inline(never)]
pub unsafe fn syscall5(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall 0",
            in("$r11") nr,
            inlateout("$r4") a0 => ret,
            inlateout("$r5") a1 => _,
            inlateout("$r6") a2 => _,
            inlateout("$r7") a3 => _,
            inlateout("$r8") a4 => _,
        );
    }
    ret
}

#[inline(never)]
pub unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall 0",
            in("$r11") nr,
            inlateout("$r4") a0 => ret,
            inlateout("$r5") a1 => _,
            inlateout("$r6") a2 => _,
            inlateout("$r7") a3 => _,
            inlateout("$r8") a4 => _,
            inlateout("$r9") a5 => _,
        );
    }
    ret
}
