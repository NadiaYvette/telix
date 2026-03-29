// Telix kernel entry point for MIPS64 (QEMU Malta).
//
// QEMU loads ELF at KSEG0 (0xFFFFFFFF80100000).
// CPU enters in kernel mode. No arguments passed.

.set noreorder
.set mips64r2

.section .text.boot, "ax"
.global _start

_start:
    // Disable interrupts, set KX/SX/UX for 64-bit addressing.
    mfc0    $t0, $12            // CP0.Status
    li      $t1, 0x00000004     // Clear ERL
    not     $t1
    and     $t0, $t0, $t1
    li      $t1, 0xe0           // Set KX=SX=UX (bits 7:5)
    or      $t0, $t0, $t1
    li      $t1, 0x1            // Clear IE (disable interrupts)
    not     $t1
    and     $t0, $t0, $t1
    mtc0    $t0, $12
    ehb

    // Zero BSS.
    dla     $t0, __bss_start
    dla     $t1, __bss_end
.bss_loop:
    bgeu    $t0, $t1, .bss_done
    nop
    sd      $zero, 0($t0)
    daddiu  $t0, $t0, 8
    b       .bss_loop
    nop
.bss_done:

    // Set up boot stack.
    dla     $sp, __boot_stack_top

    // Call Rust entry.
    dla     $t0, _rust_entry
    jalr    $t0
    nop

    // Should not return.
.halt:
    wait
    b       .halt
    nop

// Boot stack: 64 KiB in BSS.
.section .bss.boot_stack, "aw", @nobits
.balign 16
__boot_stack_bottom:
    .space  65536
.global __boot_stack_top
__boot_stack_top:
