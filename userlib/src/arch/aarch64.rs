//! AArch64 raw syscall stubs via svc #0.
//!
//! ABI: number in x8, args in x0-x5, return in x0.

#[inline(always)]
pub unsafe fn syscall0(nr: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            lateout("x0") ret,
            lateout("x1") _,
            lateout("x2") _,
            lateout("x3") _,
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall1(nr: u64, a0: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 => ret,
            lateout("x1") _,
            lateout("x2") _,
            lateout("x3") _,
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 => ret,
            inlateout("x1") a1 => _,
            lateout("x2") _,
            lateout("x3") _,
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 => ret,
            inlateout("x1") a1 => _,
            inlateout("x2") a2 => _,
            lateout("x3") _,
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 => ret,
            inlateout("x1") a1 => _,
            inlateout("x2") a2 => _,
            inlateout("x3") a3 => _,
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall5(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 => ret,
            inlateout("x1") a1 => _,
            inlateout("x2") a2 => _,
            inlateout("x3") a3 => _,
            inlateout("x4") a4 => _,
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a0 => ret,
            inlateout("x1") a1 => _,
            inlateout("x2") a2 => _,
            inlateout("x3") a3 => _,
            inlateout("x4") a4 => _,
            inlateout("x5") a5 => _,
        );
    }
    ret
}
