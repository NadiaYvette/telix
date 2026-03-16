// Telix kernel entry point for RISC-V 64.
//
// QEMU virt machine with OpenSBI loads the kernel at 0x80200000.
// CPU enters in S-mode. a0 = hart ID, a1 = DTB pointer.
// The boot hart may be any hart (not necessarily 0).

.section .text.boot, "ax"
.global _start

_start:
    // Use an atomic flag to ensure only one hart proceeds.
    // amoswap: atomically swap 1 into _boot_lock, get old value.
    la      t0, _boot_lock
    li      t1, 1
    amoswap.w.aq t2, t1, (t0)
    bnez    t2, .secondary_spin   // If old value != 0, another hart got here first.

    // Save hart ID and DTB pointer before we clobber them.
    mv      s0, a0                // s0 = hart ID (callee-saved)
    mv      s1, a1                // s1 = DTB pointer (callee-saved)

    // Zero BSS.
    la      t0, __bss_start
    la      t1, __bss_end
.bss_loop:
    bgeu    t0, t1, .bss_done
    sd      zero, 0(t0)
    addi    t0, t0, 8
    j       .bss_loop
.bss_done:

    // Set up boot stack (grows downward from top of __boot_stack_top).
    la      sp, __boot_stack_top

    // Pass DTB pointer as first argument to Rust entry.
    mv      a0, s1
    call    _rust_entry

    // Should not return; halt if it does.
.halt:
    wfi
    j       .halt

.secondary_spin:
    wfi
    j       .secondary_spin

// Atomic boot lock (in data section so it's zero-initialized before BSS clear).
.section .data
.balign 4
_boot_lock:
    .word   0

// Boot stack: 64 KiB in BSS.
.section .bss.boot_stack, "aw", @nobits
.balign 16
__boot_stack_bottom:
    .space  65536
.global __boot_stack_top
__boot_stack_top:
