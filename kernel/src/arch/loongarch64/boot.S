// LoongArch64 boot entry point (QEMU virt).
// Placeholder — will be implemented in commit 2.

.section .text.boot
.global _start
_start:
    // TODO: BSS clear, stack setup, call _rust_entry
    b _start
