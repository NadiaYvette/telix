/* RISC-V 64 setjmp / longjmp for Telix.
 * jmp_buf layout (unsigned long [24]):
 *   [0]  = s0  (fp)
 *   [1]  = s1
 *   [2]  = s2
 *   [3]  = s3
 *   [4]  = s4
 *   [5]  = s5
 *   [6]  = s6
 *   [7]  = s7
 *   [8]  = s8
 *   [9]  = s9
 *   [10] = s10
 *   [11] = s11
 *   [12] = sp
 *   [13] = ra
 */

.text
.global setjmp
.type setjmp, @function
setjmp:
    sd   s0,   0(a0)
    sd   s1,   8(a0)
    sd   s2,  16(a0)
    sd   s3,  24(a0)
    sd   s4,  32(a0)
    sd   s5,  40(a0)
    sd   s6,  48(a0)
    sd   s7,  56(a0)
    sd   s8,  64(a0)
    sd   s9,  72(a0)
    sd   s10, 80(a0)
    sd   s11, 88(a0)
    sd   sp,  96(a0)
    sd   ra, 104(a0)
    li   a0, 0
    ret
.size setjmp, . - setjmp

.global longjmp
.type longjmp, @function
longjmp:
    ld   s0,   0(a0)
    ld   s1,   8(a0)
    ld   s2,  16(a0)
    ld   s3,  24(a0)
    ld   s4,  32(a0)
    ld   s5,  40(a0)
    ld   s6,  48(a0)
    ld   s7,  56(a0)
    ld   s8,  64(a0)
    ld   s9,  72(a0)
    ld   s10, 80(a0)
    ld   s11, 88(a0)
    ld   sp,  96(a0)
    ld   ra, 104(a0)
    /* Return val, but if val == 0 return 1 */
    seqz a0, a1
    add  a0, a0, a1
    ret
.size longjmp, . - longjmp
