/* x86-64 setjmp / longjmp for Telix.
 * jmp_buf layout (unsigned long [24]):
 *   [0]  = rbx
 *   [1]  = rbp
 *   [2]  = r12
 *   [3]  = r13
 *   [4]  = r14
 *   [5]  = r15
 *   [6]  = rsp  (after return — points past return address)
 *   [7]  = rip  (return address)
 */

.text
.global setjmp
.type setjmp, @function
setjmp:
    mov  %rbx,    (%rdi)
    mov  %rbp,   8(%rdi)
    mov  %r12,  16(%rdi)
    mov  %r13,  24(%rdi)
    mov  %r14,  32(%rdi)
    mov  %r15,  40(%rdi)
    /* Save rsp as it will be after our ret (skip return address on stack) */
    lea  8(%rsp), %rax
    mov  %rax,  48(%rdi)
    /* Save return address */
    mov  (%rsp), %rax
    mov  %rax,  56(%rdi)
    xor  %eax, %eax
    ret
.size setjmp, . - setjmp

.global longjmp
.type longjmp, @function
longjmp:
    mov  %esi, %eax
    /* If val == 0, return 1 */
    test %eax, %eax
    jnz  1f
    inc  %eax
1:
    mov    (%rdi), %rbx
    mov   8(%rdi), %rbp
    mov  16(%rdi), %r12
    mov  24(%rdi), %r13
    mov  32(%rdi), %r14
    mov  40(%rdi), %r15
    mov  48(%rdi), %rsp
    jmp *56(%rdi)
.size longjmp, . - longjmp
