/* Raw syscall stubs for Telix riscv64.
 *
 * ABI: number in a7, args in a0-a5, return in a0.
 * Trap via: ecall
 */

    .section .text

/* uint64_t __telix_syscall0(uint64_t nr) */
    .global __telix_syscall0
    .type __telix_syscall0, @function
__telix_syscall0:
    mv a7, a0
    ecall
    ret
    .size __telix_syscall0, . - __telix_syscall0

/* uint64_t __telix_syscall1(uint64_t nr, uint64_t a0) */
    .global __telix_syscall1
    .type __telix_syscall1, @function
__telix_syscall1:
    mv a7, a0
    mv a0, a1
    ecall
    ret
    .size __telix_syscall1, . - __telix_syscall1

/* uint64_t __telix_syscall2(uint64_t nr, uint64_t a0, uint64_t a1) */
    .global __telix_syscall2
    .type __telix_syscall2, @function
__telix_syscall2:
    mv a7, a0
    mv a0, a1
    mv a1, a2
    ecall
    ret
    .size __telix_syscall2, . - __telix_syscall2

/* uint64_t __telix_syscall3(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2) */
    .global __telix_syscall3
    .type __telix_syscall3, @function
__telix_syscall3:
    mv a7, a0
    mv a0, a1
    mv a1, a2
    mv a2, a3
    ecall
    ret
    .size __telix_syscall3, . - __telix_syscall3

/* uint64_t __telix_syscall4(uint64_t nr, uint64_t a0, ..., uint64_t a3) */
    .global __telix_syscall4
    .type __telix_syscall4, @function
__telix_syscall4:
    mv a7, a0
    mv a0, a1
    mv a1, a2
    mv a2, a3
    mv a3, a4
    ecall
    ret
    .size __telix_syscall4, . - __telix_syscall4

/* uint64_t __telix_syscall6(uint64_t nr, uint64_t a0, ..., uint64_t a5)
 * C ABI: a0=nr, a1=a0, a2=a1, a3=a2, a4=a3, a5=a4, a6=a5
 */
    .global __telix_syscall6
    .type __telix_syscall6, @function
__telix_syscall6:
    mv a7, a0
    mv a0, a1
    mv a1, a2
    mv a2, a3
    mv a3, a4
    mv a4, a5
    mv a5, a6
    ecall
    ret
    .size __telix_syscall6, . - __telix_syscall6

/* uint64_t __telix_recv_msg(uint32_t port, struct telix_msg *out)
 *
 * Performs SYS_RECV (blocking) and writes the full message into *out.
 * Kernel returns on riscv64:
 *   a0=status, a1=tag, a2=data[0], a3=data[1],
 *   a4=data[2], a5=data[3], a6=data[4], a7=data[5]
 *
 * C args: a0=port, a1=out
 * Returns status in a0.
 */
    .global __telix_recv_msg
    .type __telix_recv_msg, @function
__telix_recv_msg:
    /* Save out pointer and ra in callee-saved registers. */
    addi sp, sp, -16
    sd s0, 0(sp)
    sd ra, 8(sp)
    mv s0, a1               /* save out pointer */
    li a7, 4                 /* SYS_RECV = 4 */
    /* a0 already contains port */
    ecall
    /* Store results into struct telix_msg at s0 */
    sd a1, 0(s0)             /* out->tag */
    sd a2, 8(s0)             /* out->data[0] */
    sd a3, 16(s0)            /* out->data[1] */
    sd a4, 24(s0)            /* out->data[2] */
    sd a5, 32(s0)            /* out->data[3] */
    sd a6, 40(s0)            /* out->data[4] */
    sd a7, 48(s0)            /* out->data[5] */
    /* a0 still has status */
    ld s0, 0(sp)
    ld ra, 8(sp)
    addi sp, sp, 16
    ret
    .size __telix_recv_msg, . - __telix_recv_msg

/* uint64_t __telix_call_msg(uint32_t port, uint64_t tag,
 *                           uint64_t d0, uint64_t d1,
 *                           uint64_t d2, uint64_t d3,
 *                           struct telix_msg *out)
 *
 * SYS_CALL (118): send (tag,d0..d3) to port, block until reply, write reply
 * into *out.  Faithful mirror of __telix_recv_msg (same reply capture); on
 * riscv64 the C-arg regs a0-a5 already equal the syscall args
 * (port,tag,d0,d1,d2,d3), and the 7th C arg (out) is in a6.
 * Kernel returns: a0=status, a1=tag, a2..a7=data[0..5].
 */
    .global __telix_call_msg
    .type __telix_call_msg, @function
__telix_call_msg:
    addi sp, sp, -16
    sd s0, 0(sp)
    sd ra, 8(sp)
    mv s0, a6                /* save out pointer (7th C arg) */
    li a7, 118               /* SYS_CALL = 118 */
    /* a0-a5 already = port,tag,d0,d1,d2,d3 */
    ecall
    sd a1, 0(s0)             /* out->tag */
    sd a2, 8(s0)             /* out->data[0] */
    sd a3, 16(s0)            /* out->data[1] */
    sd a4, 24(s0)            /* out->data[2] */
    sd a5, 32(s0)            /* out->data[3] */
    sd a6, 40(s0)            /* out->data[4] */
    sd a7, 48(s0)            /* out->data[5] */
    /* a0 still has status */
    ld s0, 0(sp)
    ld ra, 8(sp)
    addi sp, sp, 16
    ret
    .size __telix_call_msg, . - __telix_call_msg
