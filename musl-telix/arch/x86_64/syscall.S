/* Raw syscall stubs for Telix x86_64.
 *
 * ABI: number in rax, args in rdi/rsi/rdx/r10/r8/r9, return in rax.
 * Trap via: int $0x80
 * Clobbers: rcx, r11 (per kernel convention).
 */

    .section .text

/* uint64_t __telix_syscall0(uint64_t nr) */
    .global __telix_syscall0
    .type __telix_syscall0, @function
__telix_syscall0:
    mov %rdi, %rax
    int $0x80
    ret
    .size __telix_syscall0, . - __telix_syscall0

/* uint64_t __telix_syscall1(uint64_t nr, uint64_t a0) */
    .global __telix_syscall1
    .type __telix_syscall1, @function
__telix_syscall1:
    mov %rdi, %rax
    mov %rsi, %rdi
    int $0x80
    ret
    .size __telix_syscall1, . - __telix_syscall1

/* uint64_t __telix_syscall2(uint64_t nr, uint64_t a0, uint64_t a1) */
    .global __telix_syscall2
    .type __telix_syscall2, @function
__telix_syscall2:
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    int $0x80
    ret
    .size __telix_syscall2, . - __telix_syscall2

/* uint64_t __telix_syscall3(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2) */
    .global __telix_syscall3
    .type __telix_syscall3, @function
__telix_syscall3:
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %rcx, %rdx
    int $0x80
    ret
    .size __telix_syscall3, . - __telix_syscall3

/* uint64_t __telix_syscall4(uint64_t nr, uint64_t a0, ..., uint64_t a3)
 * C calling convention: rdi=nr, rsi=a0, rdx=a1, rcx=a2, r8=a3
 */
    .global __telix_syscall4
    .type __telix_syscall4, @function
__telix_syscall4:
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %r8, %r10
    mov %rcx, %rdx
    int $0x80
    ret
    .size __telix_syscall4, . - __telix_syscall4

/* uint64_t __telix_syscall6(uint64_t nr, uint64_t a0, ..., uint64_t a5)
 * C calling convention: rdi=nr, rsi=a0, rdx=a1, rcx=a2, r8=a3, r9=a4, 8(%rsp)=a5
 */
    .global __telix_syscall6
    .type __telix_syscall6, @function
__telix_syscall6:
    mov %rdi, %rax
    mov %rsi, %rdi
    mov %rdx, %rsi
    mov %r8, %r10
    mov %rcx, %rdx
    mov %r9, %r8
    mov 8(%rsp), %r9
    int $0x80
    ret
    .size __telix_syscall6, . - __telix_syscall6

/* uint64_t __telix_recv_msg(uint32_t port, struct telix_msg *out)
 *
 * Performs SYS_RECV (blocking) and writes the full message into *out.
 * Kernel returns on x86_64:
 *   rax=status, rdi=tag, rsi=data[0], rdx=data[1],
 *   r10=data[2], r8=data[3], r9=data[4], rbx=data[5]
 *
 * C args: rdi=port, rsi=out
 * Returns status in rax.
 */
    .global __telix_recv_msg
    .type __telix_recv_msg, @function
__telix_recv_msg:
    push %rbx
    push %r12
    mov %rsi, %r12          /* save out pointer in callee-saved r12 */
    mov $4, %rax            /* SYS_RECV = 4 */
    /* rdi already contains port */
    int $0x80
    /* Store results into struct telix_msg at r12 */
    mov %rdi, 0(%r12)       /* out->tag */
    mov %rsi, 8(%r12)       /* out->data[0] */
    mov %rdx, 16(%r12)      /* out->data[1] */
    mov %r10, 24(%r12)      /* out->data[2] */
    mov %r8,  32(%r12)      /* out->data[3] */
    mov %r9,  40(%r12)      /* out->data[4] */
    mov %rbx, 48(%r12)      /* out->data[5] */
    /* rax still has status */
    pop %r12
    pop %rbx
    ret
    .size __telix_recv_msg, . - __telix_recv_msg
