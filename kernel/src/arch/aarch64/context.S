// Context switch: save callee-saved registers of prev, restore next.
//
// void context_switch(CpuContext *prev, CpuContext *next)
//   x0 = pointer to prev CpuContext
//   x1 = pointer to next CpuContext
//
// CpuContext layout (offsets in bytes):
//   0x00: x19
//   0x08: x20
//   0x10: x21
//   0x18: x22
//   0x20: x23
//   0x28: x24
//   0x30: x25
//   0x38: x26
//   0x40: x27
//   0x48: x28
//   0x50: x29 (fp)
//   0x58: x30 (lr)
//   0x60: sp

.global context_switch
context_switch:
    // Save callee-saved registers of the outgoing thread.
    stp x19, x20, [x0, #0x00]
    stp x21, x22, [x0, #0x10]
    stp x23, x24, [x0, #0x20]
    stp x25, x26, [x0, #0x30]
    stp x27, x28, [x0, #0x40]
    stp x29, x30, [x0, #0x50]
    mov x9, sp
    str x9, [x0, #0x60]

    // Restore callee-saved registers of the incoming thread.
    ldp x19, x20, [x1, #0x00]
    ldp x21, x22, [x1, #0x10]
    ldp x23, x24, [x1, #0x20]
    ldp x25, x26, [x1, #0x30]
    ldp x27, x28, [x1, #0x40]
    ldp x29, x30, [x1, #0x50]
    ldr x9, [x1, #0x60]
    mov sp, x9

    // Return to the new thread via its x30 (LR).
    ret
