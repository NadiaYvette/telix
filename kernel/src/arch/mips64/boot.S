// MIPS64 boot entry point (QEMU Malta).
// Placeholder — will be implemented in commit 6.

.section .text.boot
.global _start
_start:
    // TODO: CP0 Status setup, BSS clear, stack setup, call _rust_entry
    b _start
