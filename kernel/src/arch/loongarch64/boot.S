// Telix kernel entry point for LoongArch64.
//
// QEMU virt machine loads ELF at PA 0x200000, enters at _start in PLV0.
// CRMD.DA=1 (direct address translation), MMU off.
// a0 = core id, a1 may contain FW_CFG or 0.

.section .text.boot, "ax"
.global _start

_start:
    // Use an atomic flag to ensure only one core proceeds.
    la.pcrel  $t0, _boot_lock
    li.w      $t1, 1
    amadd.w   $t2, $t1, $t0      // t2 = old value, *t0 += 1
    bnez      $t2, .secondary_spin

    // Save arguments.
    move      $s0, $a0            // s0 = core id
    move      $s1, $a1            // s1 = fw_cfg pointer

    // Zero BSS.
    la.pcrel  $t0, __bss_start
    la.pcrel  $t1, __bss_end
.bss_loop:
    bgeu      $t0, $t1, .bss_done
    st.d      $zero, $t0, 0
    addi.d    $t0, $t0, 8
    b         .bss_loop
.bss_done:

    // Set up boot stack.
    la.pcrel  $sp, __boot_stack_top

    // Call Rust entry. a0 = core_id, a1 = fw_cfg pointer.
    move      $a0, $s0
    move      $a1, $s1
    bl        _rust_entry

    // Should not return.
.halt:
    idle      0
    b         .halt

.secondary_spin:
    idle      0
    b         .secondary_spin

// Atomic boot lock.
.section .data
.balign 4
_boot_lock:
    .word     0

// Boot stack: 64 KiB in BSS.
.section .bss.boot_stack, "aw", @nobits
.balign 16
__boot_stack_bottom:
    .space    65536
.global __boot_stack_top
__boot_stack_top:
