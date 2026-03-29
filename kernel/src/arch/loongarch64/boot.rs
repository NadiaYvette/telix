//! LoongArch64 boot support.

unsafe extern "C" {
    static __bss_end: u8;
}

/// Physical address past the kernel image.
pub fn kernel_end_addr() -> usize {
    unsafe { &__bss_end as *const u8 as usize }
}
