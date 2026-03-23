/* CRT startup for Telix aarch64 userspace C programs.
 *
 * The kernel places arg0 in x0, arg1 in x1, arg2 in x2.
 * We save them, call __telix_init(), restore args, call main(),
 * then call _exit(return_value).
 */

    .section .text
    .global _start
    .type _start, @function
_start:
    /* Save args in callee-saved registers. */
    mov x19, x0             /* save arg0 */
    mov x20, x1             /* save arg1 */
    mov x21, x2             /* save arg2 */
    bl __telix_init          /* C runtime init */
    mov x0, x19              /* restore arg0 */
    mov x1, x20              /* restore arg1 */
    mov x2, x21              /* restore arg2 */
    bl main
    /* x0 = return value = exit code */
    bl _exit
    brk #0                   /* unreachable */
    .size _start, . - _start
