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

// Secondary CPUs reach here ONLY on platforms that launch every core
// at the kernel entry point (none of our current targets do — QEMU
// virt halts APs at reset and starts them via the MailBox+IPI wake
// protocol implemented in smp::start_secondary_cpus).  Kept as a
// safety net: an AP that arrives via the boot_lock branch falls into
// `ap_wake_entry` below, which is the same entry the wake-IPI's
// firmware stub jumps to.  Either way the AP ends up in
// secondary_rust_entry with the right stack.
.secondary_spin:
    b         ap_wake_entry

// #257 LoongArch SMP wake entry point.  Reached either from the
// `.secondary_spin` fallback or — on QEMU virt and real 3A5000
// hardware — from the firmware stub that wakes the AP after the BSP
// stamps this label's VA into the AP's MailBox0 and sends
// ACTION_BOOT_CPU.
//
// Identity to the BSP's `_start` body from here on: install DMW
// windows so high-half VAs work, look up our stack from
// `_ap_entry_slot[CSR.CPUID].stack_top`, then call
// `secondary_rust_entry`.
.global ap_wake_entry
ap_wake_entry:
    // Direct-map windows: DMW0=cached (VSEG=0x9), DMW1=uncached MMIO
    // (VSEG=0x8).  Matches the BSP's _rust_entry preamble so post-wake
    // APs can touch the kernel image + IOCSR space without paging on.
    li.d      $t0, 0x9000000000000011  // VSEG=0x9, MAT=cached, PLV0
    csrwr     $t0, 0x180          // CSR.DMW0
    li.d      $t0, 0x8000000000000001  // VSEG=0x8, MAT=uncached, PLV0
    csrwr     $t0, 0x181          // CSR.DMW1
    dbar      0

    // CSR.CPUID is the authoritative core identity post-wake; firmware
    // may not populate $a0 the way `_start` does for the BSP.
    csrrd     $t0, 0x20           // CSR.CPUID
    la.pcrel  $t1, _ap_entry_slot
    slli.d    $t2, $t0, 4         // cpuid * 16 (slot stride)
    add.d     $t1, $t1, $t2
    ld.d      $sp, $t1, 8         // stack_top (filled by BSP pre-wake)
    move      $a0, $t0            // cpuid → secondary_rust_entry arg 0
    bl        secondary_rust_entry
    // Should not return; halt if it does.
.ap_unreachable:
    idle      0
    b         .ap_unreachable

// Atomic boot lock.
.section .data
.balign 4
_boot_lock:
    .word     0

// Per-core (entry, stack_top) slots, 16 B each.  BSP writes these from
// arch::loongarch64::smp::start_secondary_cpus(); secondaries poll them
// in .ap_poll above.  Sized for MAX_CPUS=4.
.section .bss._ap_entry_slot, "aw", @nobits
.balign 16
.global _ap_entry_slot
_ap_entry_slot:
    .space    64

// Boot stack: 64 KiB in BSS.
.section .bss.boot_stack, "aw", @nobits
.balign 16
__boot_stack_bottom:
    .space    65536
.global __boot_stack_top
__boot_stack_top:
