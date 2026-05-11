/* Phase 200 (#136) probe-α: direct clone3 without libpthread.
 *
 * Bypasses glibc's start_thread / TLS bootstrap to isolate whether the
 * pthread wedge is in libpthread or in the kernel's CLONE_THREAD path.
 *
 * The pthread test wedges between sigprocmask (last visible child
 * syscall) and the call to user thread_main.  All of libpthread's
 * bootstrap lives in that window — TLS-relative access, cancellation
 * setup, dtor list init, etc.  This test calls clone3 directly with
 * the same flags pthread_create uses and has the child do a direct
 * `write(1, ...)` syscall as its very first instruction.
 *
 * Outcomes:
 *   [clone_test] start          — parent reached clone3 setup
 *   [clone_child_w] (NEW THREAD) — kernel CLONE_THREAD works
 *   [clone_test] DONE           — CLONE_CHILD_CLEARTID + futex wake works
 *
 * If [clone_child_w] appears → bug is in libpthread.  Fix focus moves
 * to glibc's NPTL bootstrap on Telix.
 * If [clone_child_w] does NOT appear → bug is in the kernel CLONE_THREAD
 * plumbing (exception-frame copy, RSP setup, etc.).  Fix focus moves
 * to clone_thread_in_task.
 */
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>

struct clone_args {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
    uint64_t set_tid;
    uint64_t set_tid_size;
    uint64_t cgroup;
};

#define CLONE_VM             0x00000100
#define CLONE_FS             0x00000200
#define CLONE_FILES          0x00000400
#define CLONE_SIGHAND        0x00000800
#define CLONE_THREAD         0x00010000
#define CLONE_SYSVSEM        0x00040000
#define CLONE_CHILD_CLEARTID 0x00200000

static volatile int child_tid_storage;

__attribute__((noreturn))
static void child_entry(void) {
    const char msg[] = "[clone_child_w]\n";
    syscall(SYS_write, 1, msg, sizeof(msg) - 1);
    syscall(SYS_exit, 0);
    __builtin_unreachable();
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    const char m1[] = "[clone_test] start\n";
    syscall(SYS_write, 1, m1, sizeof(m1) - 1);

    const size_t STACK_SIZE = 64 * 1024;
    void *stack_base = mmap(NULL, STACK_SIZE,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack_base == MAP_FAILED) {
        const char e[] = "[clone_test] mmap FAILED\n";
        syscall(SYS_write, 1, e, sizeof(e) - 1);
        return 1;
    }

    struct clone_args args = {
        .flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND
               | CLONE_THREAD | CLONE_SYSVSEM | CLONE_CHILD_CLEARTID,
        .pidfd = 0,
        .child_tid = (uint64_t)(uintptr_t)&child_tid_storage,
        .parent_tid = 0,
        .exit_signal = 0,
        .stack = (uint64_t)(uintptr_t)stack_base,
        .stack_size = STACK_SIZE,
        .tls = 0,
        .set_tid = 0,
        .set_tid_size = 0,
        .cgroup = 0,
    };

    long ret = syscall(SYS_clone3, &args, sizeof(args));
    if (ret == 0) {
        child_entry();
    }
    if (ret < 0) {
        const char e[] = "[clone_test] clone3 FAILED\n";
        syscall(SYS_write, 1, e, sizeof(e) - 1);
        return 2;
    }

    {
        const char m2[] = "[clone_test] clone3 ok, waiting\n";
        syscall(SYS_write, 1, m2, sizeof(m2) - 1);
    }

    /* CLONE_CHILD_CLEARTID semantics: when the child calls __NR_EXIT,
     * the kernel writes 0 to child_tid_storage and FUTEX_WAKE on that
     * address.  Spin briefly first, then sleep on futex if needed. */
    for (int i = 0; i < 10000 && child_tid_storage != 0; i++) {
        /* user-space spin */
    }
    while (child_tid_storage != 0) {
        int cur = child_tid_storage;
        if (cur == 0) break;
        syscall(SYS_futex, &child_tid_storage,
                0 /*FUTEX_WAIT*/ | 128 /*PRIVATE*/, cur, NULL, NULL, 0);
    }

    const char done[] = "[clone_test] DONE\n";
    syscall(SYS_write, 1, done, sizeof(done) - 1);
    return 0;
}
