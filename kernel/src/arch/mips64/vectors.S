// MIPS64 exception entry/exit with software TLB refill.
//
// Exception vectors (EBase-relative):
//   0x000: TLB Refill (fast path — walks software page table)
//   0x180: General Exception (syscall, page fault, timer, etc.)
//
// Kernel/user detection:
//   Uses $sp sign bit: kernel $sp is in KSEG0 (bit 63 = 1, negative),
//   user $sp is in USEG (bit 63 = 0, non-negative).
//   This avoids KScratch registers which QEMU MIPS64R2-generic lacks.
//
// Page table root:
//   Stored in global variable TLB_PT_ROOT (in KSEG0).
//   Updated by switch_page_table() in mm.rs.
//
// TrapScratch layout (32 bytes, from smp.rs):
//   offset 0:  kernel_sp
//   offset 8:  cpu_id
//   offset 16: user_sp (temporary)
//   offset 24: (padding)
//
// TrapFrame layout (288 bytes = 36 * 8):
//   offset 0..255:   $0-$31 (32 regs * 8 bytes)
//   offset 256:      epc  (CP0 EPC)
//   offset 264:      status (CP0 Status)
//   offset 272:      cause (CP0 Cause)
//   offset 280:      badvaddr (CP0 BadVAddr)
//
// Software PTE format (in our page tables):
//   bits [63:12] = KSEG0 address of page (KSEG0_VA & PFN_MASK)
//   bit 0 = V (valid), bit 1 = D (dirty), bits [3:2] = C (cache: 3=CC)
//
// Hardware EntryLo format:
//   bits [29:6] = PFN (PA >> 12), bits [5:3] = C, bit 2 = D, bit 1 = V, bit 0 = G
//
// Conversion: PFN bits = ((kseg0_addr & 0x1FFFFFFF) >> 12) << 6
//             flags = ((pte & 0xF) << 1) [shifts V→1, D→2, C→3:4]
// Note: must use >>12 then <<6 (not >>6) to avoid software bits [11:4]
// (PTE_SW_ZEROED, PTE_SW_REF) leaking into the EntryLo C field.

.set noreorder
.set noat
.set mips64r2

// =========================================================================
// Exception vector page — EBase points here.
// =========================================================================

.section .text.vectors, "ax"
.balign 4096
.global _exception_vectors

_exception_vectors:
// -------------------------------------------------------------------------
// Offset 0x000: TLB Refill (32-bit compatible VAs, when EXL=0)
// -------------------------------------------------------------------------
    j       _tlb_refill_handler
    nop

    // Pad to offset 0x080.
    .org _exception_vectors + 0x080

// -------------------------------------------------------------------------
// Offset 0x080: XTLB Refill (64-bit VAs, when EXL=0)
// -------------------------------------------------------------------------
// User VAs > 2 GiB (e.g. 0x100000000) have VA[63:31] != all-same,
// so the CPU dispatches to XTLB Refill at EBase+0x080, NOT TLB Refill
// at EBase+0x000. We use the same handler for both.
    j       _tlb_refill_handler
    nop

    // Pad to offset 0x180.
    .org _exception_vectors + 0x180

// -------------------------------------------------------------------------
// Offset 0x180: General Exception
// -------------------------------------------------------------------------
.global _trap_entry

_trap_entry:
    // Determine if we came from kernel or user mode by checking $sp sign bit.
    // KSEG0 (kernel) addresses have bit 63 = 1 (negative).
    // USEG (user) addresses have bit 63 = 0 (non-negative).
    bltz    $sp, .from_kernel
    nop

.from_user:
    // User-mode entry: $sp is a user VA (non-negative).
    // Save $ra and $sp in $k0/$k1, then load kernel stack from TrapScratch.
    move    $k0, $sp               // k0 = user sp
    move    $k1, $ra               // k1 = user ra

    // Load TrapScratch pointer. Single-CPU: use TRAP_SCRATCH_ARRAY[0].
    dla     $sp, TRAP_SCRATCH_ARRAY // sp = &TRAP_SCRATCH_ARRAY (KSEG0 address)
    sd      $k0, 16($sp)           // TrapScratch.user_sp = user sp
    ld      $sp, 0($sp)            // sp = TrapScratch.kernel_sp

    // Allocate trap frame on kernel stack.
    daddiu  $sp, $sp, -288

    // Save user ra and sp.
    sd      $k1, 31*8($sp)         // frame.regs[31] = user ra
    sd      $k0, 29*8($sp)         // frame.regs[29] = user sp
    b       .save_common
    nop

.from_kernel:
    // Kernel-mode entry: $sp is a kernel VA (negative/KSEG0).
    move    $k1, $ra               // save ra

    // Allocate trap frame on current kernel stack.
    daddiu  $sp, $sp, -288

    // Save ra and original sp.
    sd      $k1, 31*8($sp)         // frame.regs[31] = ra
    daddiu  $k1, $sp, 288
    sd      $k1, 29*8($sp)         // frame.regs[29] = original sp
    b       .save_common
    nop

.save_common:
    sd      $zero, 0*8($sp)
    sd      $1,  1*8($sp)
    sd      $2,  2*8($sp)
    sd      $3,  3*8($sp)
    sd      $4,  4*8($sp)
    sd      $5,  5*8($sp)
    sd      $6,  6*8($sp)
    sd      $7,  7*8($sp)
    sd      $8,  8*8($sp)
    sd      $9,  9*8($sp)
    sd      $10, 10*8($sp)
    sd      $11, 11*8($sp)
    sd      $12, 12*8($sp)
    sd      $13, 13*8($sp)
    sd      $14, 14*8($sp)
    sd      $15, 15*8($sp)
    sd      $16, 16*8($sp)
    sd      $17, 17*8($sp)
    sd      $18, 18*8($sp)
    sd      $19, 19*8($sp)
    sd      $20, 20*8($sp)
    sd      $21, 21*8($sp)
    sd      $22, 22*8($sp)
    sd      $23, 23*8($sp)
    sd      $24, 24*8($sp)
    sd      $25, 25*8($sp)
    sd      $zero, 26*8($sp)        // k0 slot
    sd      $zero, 27*8($sp)        // k1 slot
    sd      $28, 28*8($sp)          // gp
    // $29 (sp) already saved
    sd      $30, 30*8($sp)          // fp
    // $31 (ra) already saved

    // Save EPC, Status, Cause, BadVAddr.
    dmfc0   $t0, $14                // EPC
    sd      $t0, 32*8($sp)
    mfc0    $t0, $12                // Status
    sd      $t0, 33*8($sp)
    mfc0    $t0, $13                // Cause
    sd      $t0, 34*8($sp)
    dmfc0   $t0, $8                 // BadVAddr
    sd      $t0, 35*8($sp)

    // Keep EXL=1 during the handler. For syscalls that need timer preemption
    // (exit_current_thread, park_current_for_ipc), the Rust handler clears
    // EXL before calling the blocking path.

    // Call Rust trap handler: a0 = sp (pointer to TrapFrame).
    move    $a0, $sp
    dla     $t9, trap_handler
    jalr    $t9
    nop
    // Return value in v0 ($2) = (potentially new) sp.

    move    $sp, $v0

    // Disable interrupts before restore to prevent timer re-entry during
    // the critical window between loading EPC/Status and eret. The syscall
    // handler may have cleared EXL to allow preemption, so IE could still
    // be set with EXL=0. "di" clears IE atomically.
    di
    ehb

    // Restore EPC and Status.
    ld      $t0, 32*8($sp)
    dmtc0   $t0, $14                // EPC
    ehb
    ld      $t0, 33*8($sp)
    ori     $t0, $t0, 0x2           // set EXL
    mtc0    $t0, $12                // Status
    ehb

    // Check Status.KSU (bits 4:3) to determine return mode.
    // KSU=0 → kernel, KSU=2 → user.
    ld      $t0, 33*8($sp)          // reload original Status
    andi    $t1, $t0, 0x18          // KSU bits
    beqz    $t1, .restore_to_kernel
    nop

.restore_to_user:
    // Save kernel_sp to TrapScratch before returning to user.
    daddiu  $t0, $sp, 288
    dla     $t1, TRAP_SCRATCH_ARRAY
    sd      $t0, 0($t1)             // TrapScratch.kernel_sp = stack_top

    // Restore registers.
    ld      $1,  1*8($sp)
    ld      $2,  2*8($sp)
    ld      $3,  3*8($sp)
    ld      $4,  4*8($sp)
    ld      $5,  5*8($sp)
    ld      $6,  6*8($sp)
    ld      $7,  7*8($sp)
    ld      $8,  8*8($sp)
    ld      $9,  9*8($sp)
    ld      $10, 10*8($sp)
    ld      $11, 11*8($sp)
    ld      $12, 12*8($sp)
    ld      $13, 13*8($sp)
    ld      $14, 14*8($sp)
    ld      $15, 15*8($sp)
    ld      $16, 16*8($sp)
    ld      $17, 17*8($sp)
    ld      $18, 18*8($sp)
    ld      $19, 19*8($sp)
    ld      $20, 20*8($sp)
    ld      $21, 21*8($sp)
    ld      $22, 22*8($sp)
    ld      $23, 23*8($sp)
    ld      $24, 24*8($sp)
    ld      $25, 25*8($sp)
    ld      $28, 28*8($sp)
    ld      $30, 30*8($sp)
    ld      $31, 31*8($sp)

    ld      $sp, 29*8($sp)
    eret

.restore_to_kernel:
    ld      $1,  1*8($sp)
    ld      $2,  2*8($sp)
    ld      $3,  3*8($sp)
    ld      $4,  4*8($sp)
    ld      $5,  5*8($sp)
    ld      $6,  6*8($sp)
    ld      $7,  7*8($sp)
    ld      $8,  8*8($sp)
    ld      $9,  9*8($sp)
    ld      $10, 10*8($sp)
    ld      $11, 11*8($sp)
    ld      $12, 12*8($sp)
    ld      $13, 13*8($sp)
    ld      $14, 14*8($sp)
    ld      $15, 15*8($sp)
    ld      $16, 16*8($sp)
    ld      $17, 17*8($sp)
    ld      $18, 18*8($sp)
    ld      $19, 19*8($sp)
    ld      $20, 20*8($sp)
    ld      $21, 21*8($sp)
    ld      $22, 22*8($sp)
    ld      $23, 23*8($sp)
    ld      $24, 24*8($sp)
    ld      $25, 25*8($sp)
    ld      $28, 28*8($sp)
    ld      $30, 30*8($sp)
    ld      $31, 31*8($sp)

    daddiu  $sp, $sp, 288
    eret

// =========================================================================
// TLB Refill handler (shared by TLB Refill at 0x000 and XTLB Refill at 0x080).
// =========================================================================
// Software 3-level page table walk: PGD[38:30] → PMD[29:21] → PTE[20:12]
// Uses $k0/$k1 as scratch (allowed in exception handlers).

_tlb_refill_handler:
    // Load page table root from global variable (KSEG0 address).
    // TLB_PT_ROOT is defined as a Rust #[no_mangle] static in mm.rs.
    dla     $k1, TLB_PT_ROOT
    ld      $k1, 0($k1)            // k1 = page table root

    // Level 0: PGD — index = BadVAddr[38:30] (9 bits)
    dmfc0   $k0, $8                 // k0 = BadVAddr
    dsrl    $k0, $k0, 30
    andi    $k0, $k0, 0x1FF         // 9-bit index
    dsll    $k0, $k0, 3             // * 8 (entry size)
    daddu   $k0, $k1, $k0           // k0 = &PGD[index]
    ld      $k1, 0($k0)             // k1 = PGD entry
    andi    $k0, $k1, 1             // check V bit
    beqz    $k0, _tlb_refill_fail
    nop

    // Extract next-level table address: clear low 12 bits.
    // Cannot use dsrl/dsll — logical shift loses KSEG0 sign-extension
    // (0xFFFFFFFF8xxx → 0xFFFFFFF8xxx). Use AND with mask instead.
    daddiu  $k0, $zero, -0x1000     // k0 = 0xFFFFFFFFFFFFF000
    and     $k1, $k1, $k0           // k1 = KSEG0 VA of PMD table

    // Level 1: PMD — index = BadVAddr[29:21]
    dmfc0   $k0, $8                 // reload BadVAddr
    dsrl    $k0, $k0, 21
    andi    $k0, $k0, 0x1FF
    dsll    $k0, $k0, 3
    daddu   $k0, $k1, $k0
    ld      $k1, 0($k0)
    andi    $k0, $k1, 1
    beqz    $k0, _tlb_refill_fail
    nop

    // Extract PTE table address: clear low 12 bits (preserve KSEG0 prefix).
    daddiu  $k0, $zero, -0x1000     // k0 = 0xFFFFFFFFFFFFF000
    and     $k1, $k1, $k0           // k1 = KSEG0 VA of PTE table

    // Level 2: PTE — index = BadVAddr[20:12], but TLB maps pairs of pages.
    // Even PTE index = BadVAddr[20:13] (bit 0 cleared = even).
    dmfc0   $k0, $8                 // reload BadVAddr
    dsrl    $k0, $k0, 12
    andi    $k0, $k0, 0x1FE         // even index
    dsll    $k0, $k0, 3             // * 8
    daddu   $k0, $k1, $k0           // k0 = &PTE[even_index]
    // k1 is clobbered below, but we can reconstruct odd_pte = k0 + 8.

    // === Even PTE → EntryLo0 ===
    ld      $k1, 0($k0)             // k1 = even PTE (software format)
    // Save k0 in ErrorEPC temporarily (will overwrite later).
    // Cannot use EntryHi — it truncates bits 61:40 when SEGBITS < 64,
    // mangling KSEG0 addresses (0xFFFFFFFF8xxx → 0xC00003FF8xxx).
    // ErrorEPC (CP0 $30) preserves all 64 bits and is not modified
    // during normal (non-error) exceptions.
    dmtc0   $k0, $30                // ErrorEPC = &PTE[even] (temporary)

    // Convert software PTE → hardware EntryLo.
    // PTE: [63:12]=KSEG0 addr, [11:4]=software flags, [3:0]=V,D,C (hw-compatible)
    // EntryLo: [29:6]=PFN, [5:3]=C, [2]=D, [1]=V, [0]=G
    // Use dsrl 12 + dsll 6 (not dsrl 6) to avoid software bits [11:4] leaking
    // into the EntryLo C/D/V/G fields.
    li      $k0, 0x1FFFFFFF
    and     $k0, $k1, $k0           // PA (strip KSEG0 prefix), includes flags
    dsrl    $k0, $k0, 12            // PFN only (PA >> 12, flags stripped)
    dsll    $k0, $k0, 6             // PFN at EntryLo position [29:6]
    andi    $k1, $k1, 0xF           // V, D, C bits [3:0]
    dsll    $k1, $k1, 1             // shift to EntryLo positions [4:1]
    or      $k0, $k0, $k1
    dmtc0   $k0, $2                 // EntryLo0

    // === Odd PTE → EntryLo1 ===
    dmfc0   $k0, $30                // recover &PTE[even] from ErrorEPC
    ld      $k1, 8($k0)             // k1 = odd PTE = PTE[even+1]
    li      $k0, 0x1FFFFFFF
    and     $k0, $k1, $k0
    dsrl    $k0, $k0, 12
    dsll    $k0, $k0, 6
    andi    $k1, $k1, 0xF
    dsll    $k1, $k1, 1
    or      $k0, $k0, $k1
    dmtc0   $k0, $3                 // EntryLo1

    // Set up EntryHi with VPN2 from BadVAddr.
    dmfc0   $k0, $8
    dsrl    $k0, $k0, 13
    dsll    $k0, $k0, 13            // k0 = VPN2 aligned, ASID=0
    dmtc0   $k0, $10                // EntryHi

    // PageMask = 0 for 4K pages.
    mtc0    $zero, $5               // PageMask = 0
    ehb
    tlbwr                            // write random TLB entry
    eret

_tlb_refill_fail:
    // No valid PTE — fall through to general exception handler.
    // EXL is already 1 (set by CPU on entry). EPC and BadVAddr are still valid.
    // The Rust trap handler will see exccode=TLBL/TLBS and invoke the page
    // fault handler for demand paging.
    j       _trap_entry
    nop
