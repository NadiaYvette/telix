/* CRT startup for Telix MIPS64 (N64 ABI, little-endian) userspace C programs.
 *
 * The kernel places arg0 in $a0 ($4), arg1 in $a1 ($5), arg2 in $a2 ($6).
 * We save them in callee-saved registers, call __telix_init(),
 * restore args, call main(), then call _exit(return_value).
 */

    .set    noreorder
    .section .text
    .global _start
    .type   _start, @function
    .ent    _start
_start:
    /* Set up $gp — not strictly needed for static PIE-free code
     * compiled with -mno-abicalls, but zero it for safety. */
    move    $gp, $zero

    /* Save kernel-provided args in callee-saved registers. */
    move    $s0, $a0            /* save arg0 */
    move    $s1, $a1            /* save arg1 */
    move    $s2, $a2            /* save arg2 */

    /* Allocate minimal stack frame (N64 ABI requires 16-byte alignment). */
    daddiu  $sp, $sp, -16

    jal     __telix_init        /* C runtime init */
    nop                         /* branch delay slot */

    /* Restore args for main(). */
    move    $a0, $s0
    move    $a1, $s1
    move    $a2, $s2

    jal     main
    nop                         /* branch delay slot */

    /* $v0 = return value = exit code; move to $a0 for _exit(). */
    move    $a0, $v0

    jal     _exit
    nop                         /* branch delay slot */

    /* Unreachable. */
    break
    .end    _start
    .size   _start, . - _start
