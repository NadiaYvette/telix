//! Generic radix page table walker library.
//!
//! Provides shared walking logic for architectures with multi-level
//! radix translation tables (x86-64 4-level, AArch64 4-level, RISC-V Sv39 3-level).
//!
//! Architecture-specific modules implement the `PteFormat` trait and call
//! the generic walker functions, avoiding duplicated walk loops.
//!
//! Architectures with inverted page tables or software-managed TLBs can
//! implement the HAT API directly without using this library.

// Placeholder — walker implementation will be added in Phase 3.
