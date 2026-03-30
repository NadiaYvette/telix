/* MIPS64 (N64 ABI) setjmp / longjmp for Telix.
 *
 * jmp_buf layout (unsigned long [14]):
 *   [0]  = $s0 ($16)
 *   [1]  = $s1 ($17)
 *   [2]  = $s2 ($18)
 *   [3]  = $s3 ($19)
 *   [4]  = $s4 ($20)
 *   [5]  = $s5 ($21)
 *   [6]  = $s6 ($22)
 *   [7]  = $s7 ($23)
 *   [8]  = $gp ($28)
 *   [9]  = $sp ($29)
 *   [10] = $fp ($30)
 *   [11] = $ra ($31)
 */

    .set    noreorder
    .text

    .global setjmp
    .type   setjmp, @function
    .ent    setjmp
setjmp:
    sd      $s0,   0($a0)
    sd      $s1,   8($a0)
    sd      $s2,  16($a0)
    sd      $s3,  24($a0)
    sd      $s4,  32($a0)
    sd      $s5,  40($a0)
    sd      $s6,  48($a0)
    sd      $s7,  56($a0)
    sd      $gp,  64($a0)
    sd      $sp,  72($a0)
    sd      $fp,  80($a0)
    sd      $ra,  88($a0)
    jr      $ra
    move    $v0, $zero          /* return 0 (in delay slot) */
    .end    setjmp
    .size   setjmp, . - setjmp

    .global longjmp
    .type   longjmp, @function
    .ent    longjmp
longjmp:
    ld      $s0,   0($a0)
    ld      $s1,   8($a0)
    ld      $s2,  16($a0)
    ld      $s3,  24($a0)
    ld      $s4,  32($a0)
    ld      $s5,  40($a0)
    ld      $s6,  48($a0)
    ld      $s7,  56($a0)
    ld      $gp,  64($a0)
    ld      $sp,  72($a0)
    ld      $fp,  80($a0)
    ld      $ra,  88($a0)
    /* Return val, but if val == 0 return 1. */
    move    $v0, $a1
    bne     $a1, $zero, 1f
    nop
    dli     $v0, 1
1:
    jr      $ra
    nop
    .end    longjmp
    .size   longjmp, . - longjmp
