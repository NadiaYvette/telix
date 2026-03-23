/* CRT startup for Telix riscv64 userspace C programs.
 *
 * The kernel places arg0 in a0, arg1 in a1, arg2 in a2.
 * We save them, call __telix_init(), restore args, call main(),
 * then call _exit(return_value).
 */

    .section .text
    .global _start
    .type _start, @function
_start:
    /* Save args in callee-saved registers. */
    mv s0, a0               /* save arg0 */
    mv s1, a1               /* save arg1 */
    mv s2, a2               /* save arg2 */
    call __telix_init        /* C runtime init */
    mv a0, s0               /* restore arg0 */
    mv a1, s1               /* restore arg1 */
    mv a2, s2               /* restore arg2 */
    call main
    /* a0 = return value = exit code */
    call _exit
    ebreak                   /* unreachable */
    .size _start, . - _start
