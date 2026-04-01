//! MIPS64 (N64 ABI) raw syscall stubs via the syscall instruction.
//!
//! ABI: number in $v0 ($2), args in $a0-$a5 ($4-$9), return in $v0 ($2).
//!
//! NOTE: `black_box` on the return value works around potential codegen issues
//! where the compiler may use the input value of $v0 (the syscall number)
//! instead of re-reading the output after the syscall instruction.

#[inline(always)]
pub unsafe fn syscall0(nr: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("$2") nr => ret,
            lateout("$4") _,
            lateout("$5") _,
            lateout("$6") _,
        );
    }
    core::hint::black_box(ret)
}

#[inline(always)]
pub unsafe fn syscall1(nr: u64, a0: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("$2") nr => ret,
            inlateout("$4") a0 => _,
            lateout("$5") _,
            lateout("$6") _,
        );
    }
    core::hint::black_box(ret)
}

#[inline(always)]
pub unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("$2") nr => ret,
            inlateout("$4") a0 => _,
            inlateout("$5") a1 => _,
            lateout("$6") _,
        );
    }
    core::hint::black_box(ret)
}

#[inline(always)]
pub unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("$2") nr => ret,
            inlateout("$4") a0 => _,
            inlateout("$5") a1 => _,
            inlateout("$6") a2 => _,
        );
    }
    core::hint::black_box(ret)
}

#[inline(always)]
pub unsafe fn syscall4(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("$2") nr => ret,
            inlateout("$4") a0 => _,
            inlateout("$5") a1 => _,
            inlateout("$6") a2 => _,
            inlateout("$7") a3 => _,
        );
    }
    core::hint::black_box(ret)
}

#[inline(always)]
pub unsafe fn syscall5(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("$2") nr => ret,
            inlateout("$4") a0 => _,
            inlateout("$5") a1 => _,
            inlateout("$6") a2 => _,
            inlateout("$7") a3 => _,
            inlateout("$8") a4 => _,
        );
    }
    core::hint::black_box(ret)
}

#[inline(always)]
pub unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("$2") nr => ret,
            inlateout("$4") a0 => _,
            inlateout("$5") a1 => _,
            inlateout("$6") a2 => _,
            inlateout("$7") a3 => _,
            inlateout("$8") a4 => _,
            inlateout("$9") a5 => _,
        );
    }
    core::hint::black_box(ret)
}
