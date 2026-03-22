/* _exit() for Telix. */
#include <telix/syscall.h>

void _exit(int status) {
    __telix_syscall1(SYS_EXIT, (uint64_t)(unsigned int)status);
    /* Should never return. */
    for (;;) __asm__ volatile ("ud2");
}
