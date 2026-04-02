/* LoongArch64 setjmp / longjmp for Telix.
 *
 * jmp_buf layout (unsigned long [13]):
 *   [0]  = $s0 ($r23)
 *   [1]  = $s1 ($r24)
 *   [2]  = $s2 ($r25)
 *   [3]  = $s3 ($r26)
 *   [4]  = $s4 ($r27)
 *   [5]  = $s5 ($r28)
 *   [6]  = $s6 ($r29)
 *   [7]  = $s7 ($r30)
 *   [8]  = $s8 ($r31)
 *   [9]  = $fp ($r22)
 *   [10] = $sp ($r3)
 *   [11] = $ra ($r1)
 */

.text
.global setjmp
.type setjmp, @function
setjmp:
    st.d    $s0,   $a0, 0
    st.d    $s1,   $a0, 8
    st.d    $s2,   $a0, 16
    st.d    $s3,   $a0, 24
    st.d    $s4,   $a0, 32
    st.d    $s5,   $a0, 40
    st.d    $s6,   $a0, 48
    st.d    $s7,   $a0, 56
    st.d    $s8,   $a0, 64
    st.d    $fp,   $a0, 72
    st.d    $sp,   $a0, 80
    st.d    $ra,   $a0, 88
    move    $a0, $zero
    jr      $ra
.size setjmp, . - setjmp

.global longjmp
.type longjmp, @function
longjmp:
    ld.d    $s0,   $a0, 0
    ld.d    $s1,   $a0, 8
    ld.d    $s2,   $a0, 16
    ld.d    $s3,   $a0, 24
    ld.d    $s4,   $a0, 32
    ld.d    $s5,   $a0, 40
    ld.d    $s6,   $a0, 48
    ld.d    $s7,   $a0, 56
    ld.d    $s8,   $a0, 64
    ld.d    $fp,   $a0, 72
    ld.d    $sp,   $a0, 80
    ld.d    $ra,   $a0, 88
    /* Return val, but if val == 0 return 1. */
    sltui   $a0, $a1, 1         /* a0 = (a1 == 0) ? 1 : 0 */
    add.d   $a0, $a0, $a1       /* a0 = a0 + a1 */
    jr      $ra
.size longjmp, . - longjmp
