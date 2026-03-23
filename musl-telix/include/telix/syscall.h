/* Telix syscall numbers and raw stubs. */
#ifndef TELIX_SYSCALL_H
#define TELIX_SYSCALL_H

#include <stdint.h>

/* Syscall numbers (must match kernel/src/syscall/handlers.rs). */
#define SYS_DEBUG_PUTCHAR   0
#define SYS_PORT_CREATE     1
#define SYS_PORT_DESTROY    2
#define SYS_SEND            3
#define SYS_RECV            4
#define SYS_PORT_SET_CREATE 5
#define SYS_PORT_SET_ADD    6
#define SYS_YIELD           7
#define SYS_THREAD_ID       8
#define SYS_SEND_NB         9
#define SYS_RECV_NB         10
#define SYS_EXIT            11
#define SYS_SPAWN           12
#define SYS_DEBUG_PUTS      14
#define SYS_WAITPID         15
#define SYS_MMAP_ANON       16
#define SYS_MUNMAP          17
#define SYS_NSRV_PORT       23
#define SYS_GETPID          35
#define SYS_EXECVE          54
#define SYS_GETUID          75

/* Raw syscall stubs (defined in arch/x86_64/syscall.S). */
uint64_t __telix_syscall0(uint64_t nr);
uint64_t __telix_syscall1(uint64_t nr, uint64_t a0);
uint64_t __telix_syscall2(uint64_t nr, uint64_t a0, uint64_t a1);
uint64_t __telix_syscall3(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2);
uint64_t __telix_syscall6(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5);

#endif /* TELIX_SYSCALL_H */
