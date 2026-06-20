/* Raw syscall stubs for Telix LoongArch64.
 *
 * ABI: number in $a7 ($r11), args in $a0-$a5 ($r4-$r9), return in $a0 ($r4).
 * Trap via: syscall 0
 *
 * For __telix_syscallN: C arg0 = syscall number, C arg1..argN = syscall args.
 * We move the syscall number into $a7 and shift args down.
 */

    .section .text

/* uint64_t __telix_syscall0(uint64_t nr) */
    .global __telix_syscall0
    .type __telix_syscall0, @function
__telix_syscall0:
    move    $a7, $a0
    syscall 0
    jr      $ra
    .size __telix_syscall0, . - __telix_syscall0

/* uint64_t __telix_syscall1(uint64_t nr, uint64_t a0) */
    .global __telix_syscall1
    .type __telix_syscall1, @function
__telix_syscall1:
    move    $a7, $a0
    move    $a0, $a1
    syscall 0
    jr      $ra
    .size __telix_syscall1, . - __telix_syscall1

/* uint64_t __telix_syscall2(uint64_t nr, uint64_t a0, uint64_t a1) */
    .global __telix_syscall2
    .type __telix_syscall2, @function
__telix_syscall2:
    move    $a7, $a0
    move    $a0, $a1
    move    $a1, $a2
    syscall 0
    jr      $ra
    .size __telix_syscall2, . - __telix_syscall2

/* uint64_t __telix_syscall3(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2) */
    .global __telix_syscall3
    .type __telix_syscall3, @function
__telix_syscall3:
    move    $a7, $a0
    move    $a0, $a1
    move    $a1, $a2
    move    $a2, $a3
    syscall 0
    jr      $ra
    .size __telix_syscall3, . - __telix_syscall3

/* uint64_t __telix_syscall4(uint64_t nr, uint64_t a0, ..., uint64_t a3) */
    .global __telix_syscall4
    .type __telix_syscall4, @function
__telix_syscall4:
    move    $a7, $a0
    move    $a0, $a1
    move    $a1, $a2
    move    $a2, $a3
    move    $a3, $a4
    syscall 0
    jr      $ra
    .size __telix_syscall4, . - __telix_syscall4

/* uint64_t __telix_syscall6(uint64_t nr, uint64_t a0, ..., uint64_t a5)
 * C args: $r4=nr, $r5=a0, $r6=a1, $r7=a2, $r8=a3, $r9=a4, $r10=a5
 * Syscall: $r11=nr, $r4=a0, $r5=a1, $r6=a2, $r7=a3, $r8=a4, $r9=a5
 */
    .global __telix_syscall6
    .type __telix_syscall6, @function
__telix_syscall6:
    move    $a7, $a0            /* $r4 -> $r11 (nr) */
    move    $a0, $a1            /* $r5 -> $r4 (a0) */
    move    $a1, $a2            /* $r6 -> $r5 (a1) */
    move    $a2, $a3            /* $r7 -> $r6 (a2) */
    move    $a3, $a4            /* $r8 -> $r7 (a3) */
    move    $a4, $a5            /* $r9 -> $r8 (a4) */
    move    $a5, $a6            /* $r10 -> $r9 (a5) */
    syscall 0
    jr      $ra
    .size __telix_syscall6, . - __telix_syscall6

/* uint64_t __telix_recv_msg(uint32_t port, struct telix_msg *out)
 *
 * Performs SYS_RECV (blocking) and writes the full message into *out.
 * Kernel returns on LoongArch64:
 *   $r4=status, $r5=tag, $r6=data[0], $r7=data[1],
 *   $r8=data[2], $r9=data[3], $r10=data[4], $r11=data[5]
 *
 * C args: $a0($r4)=port, $a1($r5)=out
 * Returns status in $a0.
 */
    .global __telix_recv_msg
    .type __telix_recv_msg, @function
__telix_recv_msg:
    /* Save out pointer and ra on the stack. */
    addi.d  $sp, $sp, -16
    st.d    $s0, $sp, 0
    st.d    $ra, $sp, 8

    move    $s0, $a1            /* save out pointer in callee-saved $s0 */
    li.w    $a7, 4              /* SYS_RECV = 4 */
    /* $a0 already contains port */
    syscall 0

    /* Store results into struct telix_msg at $s0. */
    st.d    $a1, $s0, 0         /* out->tag       */
    st.d    $a2, $s0, 8         /* out->data[0]   */
    st.d    $a3, $s0, 16        /* out->data[1]   */
    st.d    $a4, $s0, 24        /* out->data[2]   */
    st.d    $a5, $s0, 32        /* out->data[3]   */
    st.d    $a6, $s0, 40        /* out->data[4]   */
    st.d    $a7, $s0, 48        /* out->data[5]   */

    /* $a0 still has status. */
    ld.d    $s0, $sp, 0
    ld.d    $ra, $sp, 8
    addi.d  $sp, $sp, 16
    jr      $ra
    .size __telix_recv_msg, . - __telix_recv_msg

/* uint64_t __telix_call_msg(uint32_t port, uint64_t tag,
 *                           uint64_t d0, uint64_t d1, uint64_t d2,
 *                           uint64_t d3, struct telix_msg *out)
 *
 * SYS_CALL (118): send + block-for-reply, reply written to *out.  Faithful
 * mirror of __telix_recv_msg; C-arg regs $a0-$a5 already equal the syscall
 * args (port,tag,d0,d1,d2,d3); 7th C arg (out) is in $a6.
 * Kernel returns: $a0=status, $a1=tag, $a2..$a7=data[0..5].
 */
    .global __telix_call_msg
    .type __telix_call_msg, @function
__telix_call_msg:
    addi.d  $sp, $sp, -16
    st.d    $s0, $sp, 0
    st.d    $ra, $sp, 8
    move    $s0, $a6            /* save out pointer (7th C arg) */
    li.w    $a7, 118            /* SYS_CALL = 118 */
    /* $a0-$a5 already = port,tag,d0,d1,d2,d3 */
    syscall 0
    st.d    $a1, $s0, 0         /* out->tag */
    st.d    $a2, $s0, 8         /* out->data[0] */
    st.d    $a3, $s0, 16        /* out->data[1] */
    st.d    $a4, $s0, 24        /* out->data[2] */
    st.d    $a5, $s0, 32        /* out->data[3] */
    st.d    $a6, $s0, 40        /* out->data[4] */
    st.d    $a7, $s0, 48        /* out->data[5] */
    /* $a0 still has status. */
    ld.d    $s0, $sp, 0
    ld.d    $ra, $sp, 8
    addi.d  $sp, $sp, 16
    jr      $ra
    .size __telix_call_msg, . - __telix_call_msg
