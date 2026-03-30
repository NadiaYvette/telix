/* Raw syscall stubs for Telix MIPS64 (N64 ABI, little-endian).
 *
 * ABI: number in $v0 ($2), args in $a0-$a5 ($4-$9), return in $v0 ($2).
 * Trap via: syscall instruction.
 *
 * N64 C calling convention: first 8 args in $a0-$a7 ($4-$11).
 * So C arg0 = $a0($4), C arg1 = $a1($5), ..., C arg4 = $a4($8), etc.
 *
 * IMPORTANT: Under the N64 ABI, the assembler names $t0-$t3 map to
 * $12-$15, NOT $8-$11. Registers $8-$11 are $a4-$a7 in N64.
 * We use numeric register names ($8, $9, $10, $11) to avoid ambiguity.
 *
 * For __telix_syscallN: C arg0 = syscall number, C arg1..argN = syscall args.
 * We move the syscall number into $v0 and shift args down.
 */

    .set    noreorder
    .section .text

/* uint64_t __telix_syscall0(uint64_t nr) */
    .global __telix_syscall0
    .type   __telix_syscall0, @function
    .ent    __telix_syscall0
__telix_syscall0:
    move    $v0, $a0            /* nr -> $v0 */
    syscall
    jr      $ra
    nop
    .end    __telix_syscall0
    .size   __telix_syscall0, . - __telix_syscall0

/* uint64_t __telix_syscall1(uint64_t nr, uint64_t a0) */
    .global __telix_syscall1
    .type   __telix_syscall1, @function
    .ent    __telix_syscall1
__telix_syscall1:
    move    $v0, $a0            /* nr -> $v0 */
    move    $a0, $a1            /* shift arg0 */
    syscall
    jr      $ra
    nop
    .end    __telix_syscall1
    .size   __telix_syscall1, . - __telix_syscall1

/* uint64_t __telix_syscall2(uint64_t nr, uint64_t a0, uint64_t a1) */
    .global __telix_syscall2
    .type   __telix_syscall2, @function
    .ent    __telix_syscall2
__telix_syscall2:
    move    $v0, $a0
    move    $a0, $a1
    move    $a1, $a2
    syscall
    jr      $ra
    nop
    .end    __telix_syscall2
    .size   __telix_syscall2, . - __telix_syscall2

/* uint64_t __telix_syscall3(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2) */
    .global __telix_syscall3
    .type   __telix_syscall3, @function
    .ent    __telix_syscall3
__telix_syscall3:
    move    $v0, $a0
    move    $a0, $a1
    move    $a1, $a2
    move    $a2, $a3
    syscall
    jr      $ra
    nop
    .end    __telix_syscall3
    .size   __telix_syscall3, . - __telix_syscall3

/* uint64_t __telix_syscall4(uint64_t nr, uint64_t a0, ..., uint64_t a3)
 * C args: $a0($4)=nr, $a1($5)=a0, $a2($6)=a1, $a3($7)=a2, $8=a3
 */
    .global __telix_syscall4
    .type   __telix_syscall4, @function
    .ent    __telix_syscall4
__telix_syscall4:
    move    $v0, $a0
    move    $a0, $a1
    move    $a1, $a2
    move    $a2, $a3
    move    $a3, $8             /* C arg4 ($a4/$8) -> syscall $a3 */
    syscall
    jr      $ra
    nop
    .end    __telix_syscall4
    .size   __telix_syscall4, . - __telix_syscall4

/* uint64_t __telix_syscall6(uint64_t nr, uint64_t a0, ..., uint64_t a5)
 * C args: $4=nr, $5=a0, $6=a1, $7=a2, $8=a3, $9=a4, $10=a5
 * Syscall: $v0=nr, $4=a0, $5=a1, $6=a2, $7=a3, $8=a4, $9=a5
 */
    .global __telix_syscall6
    .type   __telix_syscall6, @function
    .ent    __telix_syscall6
__telix_syscall6:
    move    $v0, $a0            /* $4 -> $v0 (nr) */
    move    $a0, $a1            /* $5 -> $4 (a0) */
    move    $a1, $a2            /* $6 -> $5 (a1) */
    move    $a2, $a3            /* $7 -> $6 (a2) */
    move    $a3, $8             /* $8 -> $7 (a3) */
    move    $8, $9              /* $9 -> $8 (a4) */
    move    $9, $10             /* $10 -> $9 (a5) */
    syscall
    jr      $ra
    nop
    .end    __telix_syscall6
    .size   __telix_syscall6, . - __telix_syscall6

/* uint64_t __telix_recv_msg(uint32_t port, struct telix_msg *out)
 *
 * Performs SYS_RECV (blocking) and writes the full message into *out.
 * Kernel returns on MIPS64:
 *   $v0($2)=status, $5=tag, $6=data[0], $7=data[1],
 *   $8=data[2], $9=data[3], $10=data[4], $11=data[5]
 *
 * C args: $a0($4)=port, $a1($5)=out
 * Returns status in $v0.
 */
    .global __telix_recv_msg
    .type   __telix_recv_msg, @function
    .ent    __telix_recv_msg
__telix_recv_msg:
    /* Save out pointer and $ra on the stack. */
    daddiu  $sp, $sp, -16
    sd      $s0, 0($sp)
    sd      $ra, 8($sp)

    move    $s0, $a1            /* save out pointer in callee-saved $s0 */
    dli     $v0, 4              /* SYS_RECV = 4 */
    /* $a0 already contains port */
    syscall

    /* Store results into struct telix_msg at $s0. */
    sd      $5, 0($s0)          /* out->tag       */
    sd      $6, 8($s0)          /* out->data[0]   */
    sd      $7, 16($s0)         /* out->data[1]   */
    sd      $8, 24($s0)         /* out->data[2]   */
    sd      $9, 32($s0)         /* out->data[3]   */
    sd      $10, 40($s0)        /* out->data[4]   */
    sd      $11, 48($s0)        /* out->data[5]   */

    /* $v0 still has status. */
    ld      $s0, 0($sp)
    ld      $ra, 8($sp)
    daddiu  $sp, $sp, 16
    jr      $ra
    nop
    .end    __telix_recv_msg
    .size   __telix_recv_msg, . - __telix_recv_msg
