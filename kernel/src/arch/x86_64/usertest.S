// x86-64 user-mode test program (runs at ring 3).
//
// Makes int 0x80 syscalls to print "EL0!\n", then digits 0-9,
// then spins yielding forever.
//
// Placed in .rodata so it can be copied to a user page.

.section .rodata.usertest, "a"
.balign 4
.global _usertest_start
.global _usertest_end

.code64
_usertest_start:
    // Print "EL0!\n" via SYS_DEBUG_PUTCHAR (nr=0 in rax, arg in rdi)
    mov     eax, 0              // SYS_DEBUG_PUTCHAR
    mov     edi, 0x45           // 'E'
    int     0x80
    mov     eax, 0
    mov     edi, 0x4C           // 'L'
    int     0x80
    mov     eax, 0
    mov     edi, 0x30           // '0'
    int     0x80
    mov     eax, 0
    mov     edi, 0x21           // '!'
    int     0x80
    mov     eax, 0
    mov     edi, 0x0A           // '\n'
    int     0x80

    // Loop: print digits '0' through '9'
    mov     ebx, 0x30           // counter = '0' (rbx is callee-saved)
.Lloop:
    mov     eax, 0              // SYS_DEBUG_PUTCHAR
    mov     edi, ebx
    int     0x80
    mov     eax, 0
    mov     edi, 0x0A           // '\n'
    int     0x80
    inc     ebx
    cmp     ebx, 0x3A           // '9' + 1
    jl      .Lloop

    // Spin forever, yielding
.Lspin:
    mov     eax, 7              // SYS_YIELD
    int     0x80
    jmp     .Lspin
_usertest_end:
