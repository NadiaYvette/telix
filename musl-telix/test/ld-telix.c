/* Minimal dynamic linker for Telix.
 *
 * Entry point: _ld_start (called by kernel when PT_INTERP is present).
 * Reads auxv from the stack, finds the main program's PT_DYNAMIC,
 * applies R_*_RELATIVE relocations, then jumps to AT_ENTRY.
 *
 * This is compiled as a PIE (-fPIE -pie) and loaded by the kernel
 * at INTERP_BASE (0x4_0000_0000).
 */
#include <stdint.h>

/* Auxiliary vector types. */
#define AT_NULL   0
#define AT_PHDR   3
#define AT_PHENT  4
#define AT_PHNUM  5
#define AT_PAGESZ 6
#define AT_BASE   7
#define AT_ENTRY  9

/* ELF types. */
#define PT_DYNAMIC 2
#define PT_LOAD    1

#define DT_NULL    0
#define DT_RELA    7
#define DT_RELASZ  8
#define DT_RELAENT 9
#define DT_REL     17
#define DT_RELSZ   18
#define DT_RELENT  19

/* Relocation types (only RELATIVE needed). */
#if defined(__aarch64__)
#define R_RELATIVE 1027   /* R_AARCH64_RELATIVE */
#elif defined(__riscv)
#define R_RELATIVE 3      /* R_RISCV_RELATIVE */
#elif defined(__x86_64__)
#define R_RELATIVE 8      /* R_X86_64_RELATIVE */
#else
#error "Unsupported architecture"
#endif

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
} Elf64_Rela;

typedef struct {
    int64_t d_tag;
    uint64_t d_val;
} Elf64_Dyn;

/* Provided by musl-telix. */
typedef long ssize_t;
typedef unsigned long size_t;
ssize_t write(int fd, const void *buf, size_t count);
void _exit(int status) __attribute__((noreturn));

static void puts_s(const char *s) {
    int n = 0;
    while (s[n]) n++;
    write(1, s, n);
}

/* Entry point — called with argc/argv/envp/auxv on the stack.
 * We extract what we need from auxv, do relocations, then jump. */
int main(int argc, char **argv, char **envp) {
    (void)argc; (void)argv;

    /* Walk past envp to find auxv. */
    char **ep = envp;
    if (ep) {
        while (*ep) ep++;
        ep++; /* skip NULL terminator */
    }
    uint64_t *auxv = (uint64_t *)ep;

    /* Parse auxv. */
    uint64_t at_phdr = 0, at_phent = 0, at_phnum = 0;
    uint64_t at_entry = 0, at_base = 0;

    if (auxv) {
        for (int i = 0; auxv[i * 2] != AT_NULL; i++) {
            uint64_t type = auxv[i * 2];
            uint64_t val  = auxv[i * 2 + 1];
            switch (type) {
                case AT_PHDR:  at_phdr = val; break;
                case AT_PHENT: at_phent = val; break;
                case AT_PHNUM: at_phnum = val; break;
                case AT_ENTRY: at_entry = val; break;
                case AT_BASE:  at_base = val; break;
            }
        }
    }

    if (at_entry == 0) {
        puts_s("ld-telix: no AT_ENTRY, cannot continue\n");
        _exit(127);
    }

    /* Find PT_DYNAMIC in the main program's phdrs. */
    Elf64_Dyn *dynamic = (void *)0;
    uint64_t load_base = 0;

    if (at_phdr && at_phent && at_phnum) {
        for (uint64_t i = 0; i < at_phnum; i++) {
            Elf64_Phdr *ph = (Elf64_Phdr *)(at_phdr + i * at_phent);
            if (ph->p_type == PT_DYNAMIC) {
                dynamic = (Elf64_Dyn *)ph->p_vaddr;
            }
            if (ph->p_type == PT_LOAD && load_base == 0) {
                load_base = ph->p_vaddr - ph->p_offset;
            }
        }
    }

    /* Process relocations if PT_DYNAMIC found. */
    if (dynamic) {
        uint64_t rela_addr = 0, rela_sz = 0, rela_ent = 0;
        uint64_t rel_addr = 0, rel_sz = 0, rel_ent = 0;

        for (Elf64_Dyn *d = dynamic; d->d_tag != DT_NULL; d++) {
            switch (d->d_tag) {
                case DT_RELA:    rela_addr = d->d_val; break;
                case DT_RELASZ:  rela_sz = d->d_val; break;
                case DT_RELAENT: rela_ent = d->d_val; break;
                case DT_REL:     rel_addr = d->d_val; break;
                case DT_RELSZ:   rel_sz = d->d_val; break;
                case DT_RELENT:  rel_ent = d->d_val; break;
            }
        }

        /* Apply RELA relocations. */
        if (rela_addr && rela_ent >= sizeof(Elf64_Rela)) {
            uint64_t count = rela_sz / rela_ent;
            Elf64_Rela *rela = (Elf64_Rela *)rela_addr;
            for (uint64_t i = 0; i < count; i++) {
                uint32_t type = (uint32_t)(rela[i].r_info & 0xFFFFFFFF);
                if (type == R_RELATIVE) {
                    uint64_t *target = (uint64_t *)(load_base + rela[i].r_offset);
                    *target = load_base + (uint64_t)rela[i].r_addend;
                }
            }
        }

        /* Apply REL relocations (no addend — read from target). */
        if (rel_addr && rel_ent >= 16) {
            (void)rel_sz; /* suppress unused warning */
            /* REL not commonly used for RELATIVE on these archs; skip for now. */
        }
    }

    puts_s("ld-telix: jumping to program entry\n");

    /* Jump to the main program's entry point. */
    void (*entry_fn)(void) = (void (*)(void))at_entry;
    entry_fn();

    /* Should not return. */
    _exit(127);
}
