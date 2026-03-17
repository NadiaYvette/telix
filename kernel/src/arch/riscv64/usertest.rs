//! Embedded user-mode test binary (raw RISC-V machine code).
//!
//! The actual instructions are in usertest.S, assembled into .rodata.
//! This module provides access to the blob via linker symbols.

unsafe extern "C" {
    static _usertest_start: u8;
    static _usertest_end: u8;
}

/// Get the user test code as a byte slice.
#[allow(dead_code)]
pub fn user_code() -> &'static [u8] {
    unsafe {
        let start = &_usertest_start as *const u8;
        let end = &_usertest_end as *const u8;
        core::slice::from_raw_parts(start, end as usize - start as usize)
    }
}
