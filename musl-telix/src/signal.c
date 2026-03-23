/* Signal handling for Telix. */
#include <telix/syscall.h>
#include <signal.h>

sighandler_t signal(int sig, sighandler_t handler) {
    /* SYS_SIGACTION(sig, handler_ptr, 0) — simplified interface.
     * The kernel sigaction takes: sig, new_handler_va, old_handler_out.
     * We pass handler as new and 0 for old. */
    uint64_t old = __telix_syscall3(SYS_SIGACTION,
        (uint64_t)sig, (uint64_t)handler, 0);
    return (sighandler_t)old;
}
