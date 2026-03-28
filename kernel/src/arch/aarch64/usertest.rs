//! Embedded user-mode test binary (raw AArch64 machine code).
//!
//! This tiny program runs at EL0 and uses SVC to make syscalls.
//! It prints "Hello from EL0!\n" via debug_putchar syscalls.

/// Raw machine code for the user test program.
/// Assembled from:
///
/// ```asm
/// _start:
///     // Print "EL0!" via SYS_DEBUG_PUTCHAR (nr=0)
///     mov x8, #0          // SYS_DEBUG_PUTCHAR
///     mov x0, #0x45       // 'E'
///     svc #0
///     mov x0, #0x4C       // 'L'
///     svc #0
///     mov x0, #0x30       // '0'
///     svc #0
///     mov x0, #0x21       // '!'
///     svc #0
///     mov x0, #0x0A       // '\n'
///     svc #0
///
///     // Loop: print a counter digit via debug_putchar
///     mov x19, #0x30      // '0' (counter, callee-saved)
/// loop:
///     mov x8, #0
///     mov x0, x19
///     svc #0
///     mov x8, #0
///     mov x0, #0x0A       // '\n'
///     svc #0
///     add x19, x19, #1
///     cmp x19, #0x3A      // '9' + 1
///     b.lt loop
///     // After '9', spin forever
/// spin:
///     mov x8, #7          // SYS_YIELD
///     svc #0
///     b spin
/// ```
#[allow(dead_code)]
#[rustfmt::skip]
pub static USER_CODE: &[u8] = &[
    // mov x8, #0
    0x08, 0x00, 0x80, 0xD2,
    // mov x0, #0x45 ('E')
    0xA0, 0x08, 0x80, 0xD2,
    // svc #0
    0x01, 0x00, 0x00, 0xD4,
    // mov x0, #0x4C ('L')
    0x80, 0x09, 0x80, 0xD2,
    // svc #0
    0x01, 0x00, 0x00, 0xD4,
    // mov x0, #0x30 ('0')
    0x00, 0x06, 0x80, 0xD2,
    // svc #0
    0x01, 0x00, 0x00, 0xD4,
    // mov x0, #0x21 ('!')
    0x20, 0x04, 0x80, 0xD2,
    // svc #0
    0x01, 0x00, 0x00, 0xD4,
    // mov x0, #0x0A ('\n')
    0x40, 0x01, 0x80, 0xD2,
    // svc #0
    0x01, 0x00, 0x00, 0xD4,
    // mov x19, #0x30 ('0')
    0x13, 0x06, 0x80, 0xD2,
    // loop: mov x8, #0
    0x08, 0x00, 0x80, 0xD2,
    // mov x0, x19
    0xE0, 0x03, 0x13, 0xAA,
    // svc #0
    0x01, 0x00, 0x00, 0xD4,
    // mov x8, #0
    0x08, 0x00, 0x80, 0xD2,
    // mov x0, #0x0A ('\n')
    0x40, 0x01, 0x80, 0xD2,
    // svc #0
    0x01, 0x00, 0x00, 0xD4,
    // add x19, x19, #1
    0x73, 0x06, 0x00, 0x91,
    // cmp x19, #0x3A
    0x7F, 0xEA, 0x00, 0xF1,
    // b.lt loop (offset = -8 instructions = -32 bytes)
    0x0B, 0xFF, 0xFF, 0x54,
    // spin: mov x8, #7 (SYS_YIELD)
    0xE8, 0x00, 0x80, 0xD2,
    // svc #0
    0x01, 0x00, 0x00, 0xD4,
    // b spin (-2 instructions = -8 bytes)
    0xFE, 0xFF, 0xFF, 0x17,
];
