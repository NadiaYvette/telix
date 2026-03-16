// Context switch: save callee-saved registers of prev, restore next.
//
// void context_switch(CpuContext *prev, CpuContext *next)
//   rdi = pointer to prev CpuContext
//   rsi = pointer to next CpuContext
//
// CpuContext layout (offsets in bytes):
//   0x00: rbx
//   0x08: rbp
//   0x10: r12
//   0x18: r13
//   0x20: r14
//   0x28: r15
//   0x30: rsp

.global context_switch
context_switch:
    // Save callee-saved registers of the outgoing thread.
    mov     [rdi + 0x00], rbx
    mov     [rdi + 0x08], rbp
    mov     [rdi + 0x10], r12
    mov     [rdi + 0x18], r13
    mov     [rdi + 0x20], r14
    mov     [rdi + 0x28], r15
    mov     [rdi + 0x30], rsp

    // Restore callee-saved registers of the incoming thread.
    mov     rbx, [rsi + 0x00]
    mov     rbp, [rsi + 0x08]
    mov     r12, [rsi + 0x10]
    mov     r13, [rsi + 0x18]
    mov     r14, [rsi + 0x20]
    mov     r15, [rsi + 0x28]
    mov     rsp, [rsi + 0x30]

    // Return to the new thread via its return address on the stack.
    ret
