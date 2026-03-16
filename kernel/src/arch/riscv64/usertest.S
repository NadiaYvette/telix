// RISC-V user-mode test program (runs at U-mode).
//
// Makes ecall syscalls to print "EL0!\n", then digits 0-9,
// then spins yielding forever.
//
// Placed in .rodata so it can be copied to a user page.

.section .rodata.usertest, "a"
.balign 4
.global _usertest_start
.global _usertest_end

_usertest_start:
    // Print "EL0!\n" via SYS_DEBUG_PUTCHAR (nr=0)
    li      a7, 0               // SYS_DEBUG_PUTCHAR
    li      a0, 0x45            // 'E'
    ecall
    li      a0, 0x4C            // 'L'
    ecall
    li      a0, 0x30            // '0'
    ecall
    li      a0, 0x21            // '!'
    ecall
    li      a0, 0x0A            // '\n'
    ecall

    // Loop: print digits '0' through '9'
    li      s0, 0x30            // counter = '0' (callee-saved)
.Lloop:
    li      a7, 0               // SYS_DEBUG_PUTCHAR
    mv      a0, s0
    ecall
    li      a7, 0
    li      a0, 0x0A            // '\n'
    ecall
    addi    s0, s0, 1
    li      t0, 0x3A            // '9' + 1
    blt     s0, t0, .Lloop

    // Spin forever, yielding
.Lspin:
    li      a7, 7               // SYS_YIELD
    ecall
    j       .Lspin
_usertest_end:
