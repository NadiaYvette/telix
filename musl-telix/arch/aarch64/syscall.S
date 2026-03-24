/* Raw syscall stubs for Telix aarch64.
 *
 * ABI: number in x8, args in x0-x5, return in x0.
 * Trap via: svc #0
 */

    .section .text

/* uint64_t __telix_syscall0(uint64_t nr) */
    .global __telix_syscall0
    .type __telix_syscall0, @function
__telix_syscall0:
    mov x8, x0
    svc #0
    ret
    .size __telix_syscall0, . - __telix_syscall0

/* uint64_t __telix_syscall1(uint64_t nr, uint64_t a0) */
    .global __telix_syscall1
    .type __telix_syscall1, @function
__telix_syscall1:
    mov x8, x0
    mov x0, x1
    svc #0
    ret
    .size __telix_syscall1, . - __telix_syscall1

/* uint64_t __telix_syscall2(uint64_t nr, uint64_t a0, uint64_t a1) */
    .global __telix_syscall2
    .type __telix_syscall2, @function
__telix_syscall2:
    mov x8, x0
    mov x0, x1
    mov x1, x2
    svc #0
    ret
    .size __telix_syscall2, . - __telix_syscall2

/* uint64_t __telix_syscall3(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2) */
    .global __telix_syscall3
    .type __telix_syscall3, @function
__telix_syscall3:
    mov x8, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    svc #0
    ret
    .size __telix_syscall3, . - __telix_syscall3

/* uint64_t __telix_syscall4(uint64_t nr, uint64_t a0, ..., uint64_t a3) */
    .global __telix_syscall4
    .type __telix_syscall4, @function
__telix_syscall4:
    mov x8, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    svc #0
    ret
    .size __telix_syscall4, . - __telix_syscall4

/* uint64_t __telix_syscall6(uint64_t nr, uint64_t a0, ..., uint64_t a5)
 * C ABI: x0=nr, x1=a0, x2=a1, x3=a2, x4=a3, x5=a4, x6=a5
 */
    .global __telix_syscall6
    .type __telix_syscall6, @function
__telix_syscall6:
    mov x8, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    mov x4, x5
    mov x5, x6
    svc #0
    ret
    .size __telix_syscall6, . - __telix_syscall6

/* uint64_t __telix_recv_msg(uint32_t port, struct telix_msg *out)
 *
 * Performs SYS_RECV (blocking) and writes the full message into *out.
 * Kernel returns on aarch64:
 *   x0=status, x1=tag, x2=data[0], x3=data[1],
 *   x4=data[2], x5=data[3], x6=data[4], x7=data[5]
 *
 * C args: x0=port, x1=out
 * Returns status in x0.
 */
    .global __telix_recv_msg
    .type __telix_recv_msg, @function
__telix_recv_msg:
    /* Save out pointer in callee-saved register. */
    stp x19, x20, [sp, #-16]!
    mov x19, x1             /* save out pointer */
    mov x8, #4              /* SYS_RECV = 4 */
    /* x0 already contains port */
    svc #0
    /* Store results into struct telix_msg at x19 */
    str x1, [x19, #0]       /* out->tag */
    str x2, [x19, #8]       /* out->data[0] */
    str x3, [x19, #16]      /* out->data[1] */
    str x4, [x19, #24]      /* out->data[2] */
    str x5, [x19, #32]      /* out->data[3] */
    str x6, [x19, #40]      /* out->data[4] */
    str x7, [x19, #48]      /* out->data[5] */
    /* x0 still has status */
    ldp x19, x20, [sp], #16
    ret
    .size __telix_recv_msg, . - __telix_recv_msg
