// x86-64 interrupt vector stubs.
//
// Generates 256 ISR stubs and a lookup table (__isr_stub_table).
// Each stub pushes a dummy error code (if CPU doesn't push one),
// pushes the vector number, saves all GPRs, calls the Rust handler,
// restores registers, and iretq.
//
// ExceptionFrame layout (matching exception.rs):
//   [SP+0]   r15
//   [SP+8]   r14
//   [SP+16]  r13
//   [SP+24]  r12
//   [SP+32]  r11
//   [SP+40]  r10
//   [SP+48]  r9
//   [SP+56]  r8
//   [SP+64]  rbp
//   [SP+72]  rdi
//   [SP+80]  rsi
//   [SP+88]  rdx
//   [SP+96]  rcx
//   [SP+104] rbx
//   [SP+112] rax
//   [SP+120] vector_number  (pushed by stub)
//   [SP+128] error_code     (real or dummy 0)
//   [SP+136] rip            (pushed by CPU)
//   [SP+144] cs
//   [SP+152] rflags
//   [SP+160] rsp
//   [SP+168] ss

.section .text.vectors, "ax"

// ==== Common ISR handler (called by all stubs) ====
__isr_common:
    push    rax
    push    rbx
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    push    rbp
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15

    // Call Rust handler: rdi = current SP (pointer to ExceptionFrame)
    mov     rdi, rsp
    call    x86_exception_handler
    // Return value in rax = (potentially new) SP for context switch
    mov     rsp, rax

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rbp
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rbx
    pop     rax

    add     rsp, 16     // Skip vector_number + error_code
    iretq

// ==== ISR stub macros ====

// Stub for vectors that DON'T have a CPU-pushed error code.
.macro isr_stub_noerr vec
    .align 16
    .global __isr_stub_\vec
    __isr_stub_\vec:
        push    0           // Dummy error code
        push    \vec        // Vector number
        jmp     __isr_common
.endm

// Stub for vectors that DO have a CPU-pushed error code.
.macro isr_stub_err vec
    .align 16
    .global __isr_stub_\vec
    __isr_stub_\vec:
        // CPU already pushed error code
        push    \vec        // Vector number
        jmp     __isr_common
.endm

// ==== Generate all 256 ISR stubs ====

// CPU exceptions 0-31 (some with error codes).
isr_stub_noerr  0       // #DE  Divide Error
isr_stub_noerr  1       // #DB  Debug
isr_stub_noerr  2       // NMI
isr_stub_noerr  3       // #BP  Breakpoint
isr_stub_noerr  4       // #OF  Overflow
isr_stub_noerr  5       // #BR  Bound Range
isr_stub_noerr  6       // #UD  Invalid Opcode
isr_stub_noerr  7       // #NM  Device Not Available
isr_stub_err    8       // #DF  Double Fault (error code)
isr_stub_noerr  9       // Coprocessor Segment Overrun (reserved)
isr_stub_err    10      // #TS  Invalid TSS (error code)
isr_stub_err    11      // #NP  Segment Not Present (error code)
isr_stub_err    12      // #SS  Stack Segment (error code)
isr_stub_err    13      // #GP  General Protection (error code)
isr_stub_err    14      // #PF  Page Fault (error code)
isr_stub_noerr  15      // Reserved
isr_stub_noerr  16      // #MF  x87 FP Exception
isr_stub_err    17      // #AC  Alignment Check (error code)
isr_stub_noerr  18      // #MC  Machine Check
isr_stub_noerr  19      // #XM  SIMD FP Exception
isr_stub_noerr  20      // Virtualization Exception
isr_stub_err    21      // #CP  Control Protection (error code)
isr_stub_noerr  22
isr_stub_noerr  23
isr_stub_noerr  24
isr_stub_noerr  25
isr_stub_noerr  26
isr_stub_noerr  27
isr_stub_noerr  28
isr_stub_noerr  29
isr_stub_noerr  30
isr_stub_noerr  31

// Hardware IRQs (vectors 32-47, remapped by PIC).
isr_stub_noerr  32      // IRQ 0: PIT Timer
isr_stub_noerr  33      // IRQ 1: Keyboard
isr_stub_noerr  34      // IRQ 2: Cascade
isr_stub_noerr  35      // IRQ 3: COM2
isr_stub_noerr  36      // IRQ 4: COM1
isr_stub_noerr  37      // IRQ 5
isr_stub_noerr  38      // IRQ 6: Floppy
isr_stub_noerr  39      // IRQ 7: Parallel
isr_stub_noerr  40      // IRQ 8: RTC
isr_stub_noerr  41      // IRQ 9
isr_stub_noerr  42      // IRQ 10
isr_stub_noerr  43      // IRQ 11
isr_stub_noerr  44      // IRQ 12: Mouse
isr_stub_noerr  45      // IRQ 13: Coprocessor
isr_stub_noerr  46      // IRQ 14: Primary ATA
isr_stub_noerr  47      // IRQ 15: Secondary ATA

// Vectors 48-127: general purpose (unused).
isr_stub_noerr  48
isr_stub_noerr  49
isr_stub_noerr  50
isr_stub_noerr  51
isr_stub_noerr  52
isr_stub_noerr  53
isr_stub_noerr  54
isr_stub_noerr  55
isr_stub_noerr  56
isr_stub_noerr  57
isr_stub_noerr  58
isr_stub_noerr  59
isr_stub_noerr  60
isr_stub_noerr  61
isr_stub_noerr  62
isr_stub_noerr  63
isr_stub_noerr  64
isr_stub_noerr  65
isr_stub_noerr  66
isr_stub_noerr  67
isr_stub_noerr  68
isr_stub_noerr  69
isr_stub_noerr  70
isr_stub_noerr  71
isr_stub_noerr  72
isr_stub_noerr  73
isr_stub_noerr  74
isr_stub_noerr  75
isr_stub_noerr  76
isr_stub_noerr  77
isr_stub_noerr  78
isr_stub_noerr  79
isr_stub_noerr  80
isr_stub_noerr  81
isr_stub_noerr  82
isr_stub_noerr  83
isr_stub_noerr  84
isr_stub_noerr  85
isr_stub_noerr  86
isr_stub_noerr  87
isr_stub_noerr  88
isr_stub_noerr  89
isr_stub_noerr  90
isr_stub_noerr  91
isr_stub_noerr  92
isr_stub_noerr  93
isr_stub_noerr  94
isr_stub_noerr  95
isr_stub_noerr  96
isr_stub_noerr  97
isr_stub_noerr  98
isr_stub_noerr  99
isr_stub_noerr  100
isr_stub_noerr  101
isr_stub_noerr  102
isr_stub_noerr  103
isr_stub_noerr  104
isr_stub_noerr  105
isr_stub_noerr  106
isr_stub_noerr  107
isr_stub_noerr  108
isr_stub_noerr  109
isr_stub_noerr  110
isr_stub_noerr  111
isr_stub_noerr  112
isr_stub_noerr  113
isr_stub_noerr  114
isr_stub_noerr  115
isr_stub_noerr  116
isr_stub_noerr  117
isr_stub_noerr  118
isr_stub_noerr  119
isr_stub_noerr  120
isr_stub_noerr  121
isr_stub_noerr  122
isr_stub_noerr  123
isr_stub_noerr  124
isr_stub_noerr  125
isr_stub_noerr  126
isr_stub_noerr  127

// Vector 128 (0x80): syscall via int 0x80.
isr_stub_noerr  128

// Vectors 129-255.
isr_stub_noerr  129
isr_stub_noerr  130
isr_stub_noerr  131
isr_stub_noerr  132
isr_stub_noerr  133
isr_stub_noerr  134
isr_stub_noerr  135
isr_stub_noerr  136
isr_stub_noerr  137
isr_stub_noerr  138
isr_stub_noerr  139
isr_stub_noerr  140
isr_stub_noerr  141
isr_stub_noerr  142
isr_stub_noerr  143
isr_stub_noerr  144
isr_stub_noerr  145
isr_stub_noerr  146
isr_stub_noerr  147
isr_stub_noerr  148
isr_stub_noerr  149
isr_stub_noerr  150
isr_stub_noerr  151
isr_stub_noerr  152
isr_stub_noerr  153
isr_stub_noerr  154
isr_stub_noerr  155
isr_stub_noerr  156
isr_stub_noerr  157
isr_stub_noerr  158
isr_stub_noerr  159
isr_stub_noerr  160
isr_stub_noerr  161
isr_stub_noerr  162
isr_stub_noerr  163
isr_stub_noerr  164
isr_stub_noerr  165
isr_stub_noerr  166
isr_stub_noerr  167
isr_stub_noerr  168
isr_stub_noerr  169
isr_stub_noerr  170
isr_stub_noerr  171
isr_stub_noerr  172
isr_stub_noerr  173
isr_stub_noerr  174
isr_stub_noerr  175
isr_stub_noerr  176
isr_stub_noerr  177
isr_stub_noerr  178
isr_stub_noerr  179
isr_stub_noerr  180
isr_stub_noerr  181
isr_stub_noerr  182
isr_stub_noerr  183
isr_stub_noerr  184
isr_stub_noerr  185
isr_stub_noerr  186
isr_stub_noerr  187
isr_stub_noerr  188
isr_stub_noerr  189
isr_stub_noerr  190
isr_stub_noerr  191
isr_stub_noerr  192
isr_stub_noerr  193
isr_stub_noerr  194
isr_stub_noerr  195
isr_stub_noerr  196
isr_stub_noerr  197
isr_stub_noerr  198
isr_stub_noerr  199
isr_stub_noerr  200
isr_stub_noerr  201
isr_stub_noerr  202
isr_stub_noerr  203
isr_stub_noerr  204
isr_stub_noerr  205
isr_stub_noerr  206
isr_stub_noerr  207
isr_stub_noerr  208
isr_stub_noerr  209
isr_stub_noerr  210
isr_stub_noerr  211
isr_stub_noerr  212
isr_stub_noerr  213
isr_stub_noerr  214
isr_stub_noerr  215
isr_stub_noerr  216
isr_stub_noerr  217
isr_stub_noerr  218
isr_stub_noerr  219
isr_stub_noerr  220
isr_stub_noerr  221
isr_stub_noerr  222
isr_stub_noerr  223
isr_stub_noerr  224
isr_stub_noerr  225
isr_stub_noerr  226
isr_stub_noerr  227
isr_stub_noerr  228
isr_stub_noerr  229
isr_stub_noerr  230
isr_stub_noerr  231
isr_stub_noerr  232
isr_stub_noerr  233
isr_stub_noerr  234
isr_stub_noerr  235
isr_stub_noerr  236
isr_stub_noerr  237
isr_stub_noerr  238
isr_stub_noerr  239
isr_stub_noerr  240
isr_stub_noerr  241
isr_stub_noerr  242
isr_stub_noerr  243
isr_stub_noerr  244
isr_stub_noerr  245
isr_stub_noerr  246
isr_stub_noerr  247
isr_stub_noerr  248
isr_stub_noerr  249
isr_stub_noerr  250
isr_stub_noerr  251
isr_stub_noerr  252
isr_stub_noerr  253
isr_stub_noerr  254
isr_stub_noerr  255

// ==== ISR stub address table ====
// Array of 256 function pointers, indexed by vector number.
// Referenced from Rust (idt.rs) via extern C __isr_stub_table.

.section .rodata.isr_table, "a"
.balign 8
.global __isr_stub_table
__isr_stub_table:
    .quad __isr_stub_0
    .quad __isr_stub_1
    .quad __isr_stub_2
    .quad __isr_stub_3
    .quad __isr_stub_4
    .quad __isr_stub_5
    .quad __isr_stub_6
    .quad __isr_stub_7
    .quad __isr_stub_8
    .quad __isr_stub_9
    .quad __isr_stub_10
    .quad __isr_stub_11
    .quad __isr_stub_12
    .quad __isr_stub_13
    .quad __isr_stub_14
    .quad __isr_stub_15
    .quad __isr_stub_16
    .quad __isr_stub_17
    .quad __isr_stub_18
    .quad __isr_stub_19
    .quad __isr_stub_20
    .quad __isr_stub_21
    .quad __isr_stub_22
    .quad __isr_stub_23
    .quad __isr_stub_24
    .quad __isr_stub_25
    .quad __isr_stub_26
    .quad __isr_stub_27
    .quad __isr_stub_28
    .quad __isr_stub_29
    .quad __isr_stub_30
    .quad __isr_stub_31
    .quad __isr_stub_32
    .quad __isr_stub_33
    .quad __isr_stub_34
    .quad __isr_stub_35
    .quad __isr_stub_36
    .quad __isr_stub_37
    .quad __isr_stub_38
    .quad __isr_stub_39
    .quad __isr_stub_40
    .quad __isr_stub_41
    .quad __isr_stub_42
    .quad __isr_stub_43
    .quad __isr_stub_44
    .quad __isr_stub_45
    .quad __isr_stub_46
    .quad __isr_stub_47
    .quad __isr_stub_48
    .quad __isr_stub_49
    .quad __isr_stub_50
    .quad __isr_stub_51
    .quad __isr_stub_52
    .quad __isr_stub_53
    .quad __isr_stub_54
    .quad __isr_stub_55
    .quad __isr_stub_56
    .quad __isr_stub_57
    .quad __isr_stub_58
    .quad __isr_stub_59
    .quad __isr_stub_60
    .quad __isr_stub_61
    .quad __isr_stub_62
    .quad __isr_stub_63
    .quad __isr_stub_64
    .quad __isr_stub_65
    .quad __isr_stub_66
    .quad __isr_stub_67
    .quad __isr_stub_68
    .quad __isr_stub_69
    .quad __isr_stub_70
    .quad __isr_stub_71
    .quad __isr_stub_72
    .quad __isr_stub_73
    .quad __isr_stub_74
    .quad __isr_stub_75
    .quad __isr_stub_76
    .quad __isr_stub_77
    .quad __isr_stub_78
    .quad __isr_stub_79
    .quad __isr_stub_80
    .quad __isr_stub_81
    .quad __isr_stub_82
    .quad __isr_stub_83
    .quad __isr_stub_84
    .quad __isr_stub_85
    .quad __isr_stub_86
    .quad __isr_stub_87
    .quad __isr_stub_88
    .quad __isr_stub_89
    .quad __isr_stub_90
    .quad __isr_stub_91
    .quad __isr_stub_92
    .quad __isr_stub_93
    .quad __isr_stub_94
    .quad __isr_stub_95
    .quad __isr_stub_96
    .quad __isr_stub_97
    .quad __isr_stub_98
    .quad __isr_stub_99
    .quad __isr_stub_100
    .quad __isr_stub_101
    .quad __isr_stub_102
    .quad __isr_stub_103
    .quad __isr_stub_104
    .quad __isr_stub_105
    .quad __isr_stub_106
    .quad __isr_stub_107
    .quad __isr_stub_108
    .quad __isr_stub_109
    .quad __isr_stub_110
    .quad __isr_stub_111
    .quad __isr_stub_112
    .quad __isr_stub_113
    .quad __isr_stub_114
    .quad __isr_stub_115
    .quad __isr_stub_116
    .quad __isr_stub_117
    .quad __isr_stub_118
    .quad __isr_stub_119
    .quad __isr_stub_120
    .quad __isr_stub_121
    .quad __isr_stub_122
    .quad __isr_stub_123
    .quad __isr_stub_124
    .quad __isr_stub_125
    .quad __isr_stub_126
    .quad __isr_stub_127
    .quad __isr_stub_128
    .quad __isr_stub_129
    .quad __isr_stub_130
    .quad __isr_stub_131
    .quad __isr_stub_132
    .quad __isr_stub_133
    .quad __isr_stub_134
    .quad __isr_stub_135
    .quad __isr_stub_136
    .quad __isr_stub_137
    .quad __isr_stub_138
    .quad __isr_stub_139
    .quad __isr_stub_140
    .quad __isr_stub_141
    .quad __isr_stub_142
    .quad __isr_stub_143
    .quad __isr_stub_144
    .quad __isr_stub_145
    .quad __isr_stub_146
    .quad __isr_stub_147
    .quad __isr_stub_148
    .quad __isr_stub_149
    .quad __isr_stub_150
    .quad __isr_stub_151
    .quad __isr_stub_152
    .quad __isr_stub_153
    .quad __isr_stub_154
    .quad __isr_stub_155
    .quad __isr_stub_156
    .quad __isr_stub_157
    .quad __isr_stub_158
    .quad __isr_stub_159
    .quad __isr_stub_160
    .quad __isr_stub_161
    .quad __isr_stub_162
    .quad __isr_stub_163
    .quad __isr_stub_164
    .quad __isr_stub_165
    .quad __isr_stub_166
    .quad __isr_stub_167
    .quad __isr_stub_168
    .quad __isr_stub_169
    .quad __isr_stub_170
    .quad __isr_stub_171
    .quad __isr_stub_172
    .quad __isr_stub_173
    .quad __isr_stub_174
    .quad __isr_stub_175
    .quad __isr_stub_176
    .quad __isr_stub_177
    .quad __isr_stub_178
    .quad __isr_stub_179
    .quad __isr_stub_180
    .quad __isr_stub_181
    .quad __isr_stub_182
    .quad __isr_stub_183
    .quad __isr_stub_184
    .quad __isr_stub_185
    .quad __isr_stub_186
    .quad __isr_stub_187
    .quad __isr_stub_188
    .quad __isr_stub_189
    .quad __isr_stub_190
    .quad __isr_stub_191
    .quad __isr_stub_192
    .quad __isr_stub_193
    .quad __isr_stub_194
    .quad __isr_stub_195
    .quad __isr_stub_196
    .quad __isr_stub_197
    .quad __isr_stub_198
    .quad __isr_stub_199
    .quad __isr_stub_200
    .quad __isr_stub_201
    .quad __isr_stub_202
    .quad __isr_stub_203
    .quad __isr_stub_204
    .quad __isr_stub_205
    .quad __isr_stub_206
    .quad __isr_stub_207
    .quad __isr_stub_208
    .quad __isr_stub_209
    .quad __isr_stub_210
    .quad __isr_stub_211
    .quad __isr_stub_212
    .quad __isr_stub_213
    .quad __isr_stub_214
    .quad __isr_stub_215
    .quad __isr_stub_216
    .quad __isr_stub_217
    .quad __isr_stub_218
    .quad __isr_stub_219
    .quad __isr_stub_220
    .quad __isr_stub_221
    .quad __isr_stub_222
    .quad __isr_stub_223
    .quad __isr_stub_224
    .quad __isr_stub_225
    .quad __isr_stub_226
    .quad __isr_stub_227
    .quad __isr_stub_228
    .quad __isr_stub_229
    .quad __isr_stub_230
    .quad __isr_stub_231
    .quad __isr_stub_232
    .quad __isr_stub_233
    .quad __isr_stub_234
    .quad __isr_stub_235
    .quad __isr_stub_236
    .quad __isr_stub_237
    .quad __isr_stub_238
    .quad __isr_stub_239
    .quad __isr_stub_240
    .quad __isr_stub_241
    .quad __isr_stub_242
    .quad __isr_stub_243
    .quad __isr_stub_244
    .quad __isr_stub_245
    .quad __isr_stub_246
    .quad __isr_stub_247
    .quad __isr_stub_248
    .quad __isr_stub_249
    .quad __isr_stub_250
    .quad __isr_stub_251
    .quad __isr_stub_252
    .quad __isr_stub_253
    .quad __isr_stub_254
    .quad __isr_stub_255
