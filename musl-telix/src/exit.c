/* _exit() for Telix. */
#include <telix/syscall.h>

void _exit(int status) {
    __telix_syscall1(SYS_EXIT, (uint64_t)(unsigned int)status);
    /* Should never return. */
#if defined(__x86_64__)
    for (;;) __asm__ volatile ("ud2");
#elif defined(__aarch64__)
    for (;;) __asm__ volatile ("brk #0");
#elif defined(__riscv)
    for (;;) __asm__ volatile ("ebreak");
#else
    for (;;) ;
#endif
}
