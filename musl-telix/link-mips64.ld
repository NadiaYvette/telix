ENTRY(_start)

SECTIONS
{
    . = 0x100000000;

    .text : { *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }

    . = ALIGN(4096);
    .data : { *(.data .data.*) }
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.MIPS.abiflags)
        *(.MIPS.options)
        *(.reginfo)
        *(.pdr)
    }
}
