ENTRY(_start)

/* Higher-half kernel: link at canonical high VMA, load at low phys.
 *
 * KERNEL_PHYS_BASE: where Multiboot/EFI bootloader places us in physical RAM.
 * KERNEL_VIRT_OFFSET: VMA - LMA = 0xFFFFFFFF80000000 (PML4[511], PDPT[510]+).
 * KERNEL_BASE: high-half virtual address corresponding to KERNEL_PHYS_BASE.
 *
 * Boot code (`.multiboot`, `.text.boot`) runs in 32-bit mode before paging,
 * so it must address itself via LMA (= PA).  It uses `symbol - KERNEL_VIRT_OFFSET`
 * in assembly to recover the LMA, but the symbols themselves still carry
 * high-half VMAs so the 64-bit code that follows the long-jump works
 * uniformly at high VMA.
 */
KERNEL_PHYS_BASE   = 0x100000;
KERNEL_VIRT_OFFSET = 0xFFFFFFFF80000000;
KERNEL_BASE        = KERNEL_PHYS_BASE + KERNEL_VIRT_OFFSET;

SECTIONS {
    . = KERNEL_BASE;

    .multiboot : AT(ADDR(.multiboot) - KERNEL_VIRT_OFFSET) ALIGN(4) {
        KEEP(*(.multiboot))
    }

    .text : AT(ADDR(.text) - KERNEL_VIRT_OFFSET) ALIGN(4K) {
        KEEP(*(.text.boot))
        *(.text .text.*)
        __text_end = .;
    }

    .rodata : AT(ADDR(.rodata) - KERNEL_VIRT_OFFSET) ALIGN(4K) {
        *(.rodata .rodata.*)
    }

    .data : AT(ADDR(.data) - KERNEL_VIRT_OFFSET) ALIGN(4K) {
        *(.data .data.*)
    }

    .bss : AT(ADDR(.bss) - KERNEL_VIRT_OFFSET) ALIGN(4K) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    . = ALIGN(4K);
    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame)
        *(.note*)
    }
}
