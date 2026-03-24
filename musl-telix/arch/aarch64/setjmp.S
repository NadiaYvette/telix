/* AArch64 setjmp / longjmp for Telix.
 * jmp_buf layout (unsigned long [24]):
 *   [0]  = x19
 *   [1]  = x20
 *   [2]  = x21
 *   [3]  = x22
 *   [4]  = x23
 *   [5]  = x24
 *   [6]  = x25
 *   [7]  = x26
 *   [8]  = x27
 *   [9]  = x28
 *   [10] = x29 (fp)
 *   [11] = x30 (lr)
 *   [12] = sp
 */

.text
.global setjmp
.type setjmp, %function
setjmp:
    stp  x19, x20, [x0, #0]
    stp  x21, x22, [x0, #16]
    stp  x23, x24, [x0, #32]
    stp  x25, x26, [x0, #48]
    stp  x27, x28, [x0, #64]
    stp  x29, x30, [x0, #80]
    mov  x2, sp
    str  x2, [x0, #96]
    mov  x0, #0
    ret
.size setjmp, . - setjmp

.global longjmp
.type longjmp, %function
longjmp:
    ldp  x19, x20, [x0, #0]
    ldp  x21, x22, [x0, #16]
    ldp  x23, x24, [x0, #32]
    ldp  x25, x26, [x0, #48]
    ldp  x27, x28, [x0, #64]
    ldp  x29, x30, [x0, #80]
    ldr  x2, [x0, #96]
    mov  sp, x2
    /* Return val, but if val == 0 return 1 */
    cmp  w1, #0
    csinc w0, w1, wzr, ne
    ret
.size longjmp, . - longjmp
