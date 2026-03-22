/* CRT startup for Telix x86_64 userspace C programs.
 *
 * The kernel places arg0 in rdi, arg1 in rsi, arg2 in rdx.
 * We save them, call __telix_init(), restore args, call main(),
 * then call _exit(return_value).
 *
 * Stack: kernel gives us a 16-byte aligned stack pointer.
 * x86_64 ABI: before `call`, rsp must be 16-byte aligned.
 * `call` pushes 8 bytes, so at function entry rsp % 16 == 8.
 */

    .section .text
    .global _start
    .type _start, @function
_start:
    /* rsp is 16-aligned from kernel. Keep it that way for calls. */
    xor %rbp, %rbp          /* clear frame pointer (end of chain) */
    mov %rdi, %r12          /* save arg0 */
    mov %rsi, %r13          /* save arg1 */
    mov %rdx, %r14          /* save arg2 */
    call __telix_init        /* C runtime init (FD table, ns_lookup) */
    mov %r12, %rdi           /* restore arg0 */
    mov %r13, %rsi           /* restore arg1 */
    mov %r14, %rdx           /* restore arg2 */
    call main
    mov %rax, %rdi           /* exit code = return value */
    call _exit
    ud2                      /* unreachable */
    .size _start, . - _start
