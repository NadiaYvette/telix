//! Architecture-specific ELF constants.
//!
//! Centralizes per-platform ELF machine type so the generic loader
//! and any future ELF consumers (core dumps, DWARF, etc.) stay
//! free of `#[cfg(target_arch)]` blocks.

/// Expected `e_machine` value for this platform's ELF binaries.
#[cfg(target_arch = "aarch64")]
pub const EM_EXPECTED: u16 = 183; // EM_AARCH64
#[cfg(target_arch = "riscv64")]
pub const EM_EXPECTED: u16 = 243; // EM_RISCV
#[cfg(target_arch = "x86_64")]
pub const EM_EXPECTED: u16 = 62; // EM_X86_64
#[cfg(target_arch = "loongarch64")]
pub const EM_EXPECTED: u16 = 258; // EM_LOONGARCH
#[cfg(target_arch = "mips64")]
pub const EM_EXPECTED: u16 = 8; // EM_MIPS
