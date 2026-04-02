/* CRT startup for Telix LoongArch64 userspace C programs.
 *
 * The kernel places arg0 in $a0 ($r4), arg1 in $a1 ($r5), arg2 in $a2 ($r6).
 * We save them in callee-saved registers, call __telix_init(),
 * restore args, call main(), then call _exit(return_value).
 *
 * LoongArch64 LP64D ABI callee-saved: $s0-$s8 ($r23-$r31), $fp ($r22).
 */

    .section .text
    .global _start
    .type _start, @function
_start:
    /* Save kernel-provided args in callee-saved registers. */
    move    $s0, $a0            /* save arg0 */
    move    $s1, $a1            /* save arg1 */
    move    $s2, $a2            /* save arg2 */

    bl      __telix_init        /* C runtime init */

    /* Restore args for main(). */
    move    $a0, $s0
    move    $a1, $s1
    move    $a2, $s2

    bl      main

    /* $a0 = return value = exit code. */
    bl      _exit

    /* Unreachable. */
    break   0
    .size _start, . - _start
