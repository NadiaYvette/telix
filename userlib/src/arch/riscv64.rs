//! RISC-V raw syscall stubs via ecall.
//!
//! ABI: number in a7, args in a0-a5, return in a0.

#[inline(always)]
pub unsafe fn syscall0(nr: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            lateout("a0") ret,
            lateout("a1") _,
            lateout("a2") _,
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall1(nr: u64, a0: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 => ret,
            lateout("a1") _,
            lateout("a2") _,
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 => ret,
            inlateout("a1") a1 => _,
            lateout("a2") _,
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 => ret,
            inlateout("a1") a1 => _,
            inlateout("a2") a2 => _,
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 => ret,
            inlateout("a1") a1 => _,
            inlateout("a2") a2 => _,
            inlateout("a3") a3 => _,
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall5(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 => ret,
            inlateout("a1") a1 => _,
            inlateout("a2") a2 => _,
            inlateout("a3") a3 => _,
            inlateout("a4") a4 => _,
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") nr,
            inlateout("a0") a0 => ret,
            inlateout("a1") a1 => _,
            inlateout("a2") a2 => _,
            inlateout("a3") a3 => _,
            inlateout("a4") a4 => _,
            inlateout("a5") a5 => _,
        );
    }
    ret
}
