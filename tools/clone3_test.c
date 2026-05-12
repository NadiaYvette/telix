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
    /* CRITICAL: Telix's mmap(MAP_ANONYMOUS) returns a VMA but does NOT
     * populate the pages.  The first write would normally fault the
     * page in — but for a child thread, an unhandled #PF on the new
     * stack kills the thread silently (boot 91amfsq641: CR2=0x200db0030
     * RIP=0x200001d5a tid=51).  Pre-touch every page from the parent
     * (which has a working fault path) so the pages are guaranteed
     * present when the child resumes execution on this stack. */
    {
        volatile char *p = (volatile char *)stack_base;
        for (size_t i = 0; i < STACK_SIZE; i += 4096) {
            p[i] = 0;
        }
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

    /* CRITICAL: clone3 + a child path written in C does NOT WORK.
     * The compiler generates RBP/RSP-relative addressing based on
     * main()'s frame layout, but the child runs on a NEW stack.
     * Boot 91amfsq641 captured the bug: Unhandled #PF CR2=0x200db0030
     * RIP=0x200001d5a — child writing 0x30 BEYOND its new RSP, killing
     * itself silently.
     *
     * Standard fix: in the child path, jump immediately to inline asm
     * that does the child's syscalls using ONLY registers, no stack
     * access until the syscall instructions complete the thread's
     * lifecycle.  The static `child_msg` lives in .rodata (shared
     * via CLONE_VM with parent — guaranteed present). */
    static const char child_msg[] = "[clone_child_w]\n";
    long ret;
    /* Stash the child_msg address into a callee-saved register (r12)
     * BEFORE the clone3 syscall.  Otherwise gcc may place it in a
     * caller-saved register that the syscall instruction clobbers
     * (rcx, r11) or that handler register-pressure invalidates,
     * leaving the child path reading garbage when it tries to load
     * %rsi for the write syscall.  Using a callee-saved reg means
     * the kernel preserves it across the clone3 vmexit. */
    __asm__ volatile (
        "mov %1, %%rdi\n"             /* arg0 = &args */
        "mov %2, %%rsi\n"             /* arg1 = sizeof(args) */
        "mov %3, %%r12\n"             /* stash child_msg in r12 */
        "mov $435, %%rax\n"           /* SYS_clone3 */
        "syscall\n"
        "test %%rax, %%rax\n"
        "jnz 2f\n"                    /* parent: jump out, ret in rax */
        /* === CHILD PATH (pure asm, no stack reads) === */
        /* write(1, child_msg, 16) — sizeof("[clone_child_w]\n") - 1 = 16 */
        "mov %%r12, %%rsi\n"          /* buf = child_msg (from r12) */
        "mov $1, %%rax\n"             /* SYS_write */
        "mov $1, %%rdi\n"             /* fd = 1 */
        "mov $16, %%rdx\n"            /* count = 16 */
        "syscall\n"
        /* int3 marker: if execution reaches HERE the kernel sees #BP
         * (vector 3) which exception_fault logs as
         * "EXCEPTION: Breakpoint (#BP) at RIP=...".  Confirms RIP
         * advancement past the first syscall instruction works. */
        "int3\n"
        /* Second write before exit — confirms execution past int3. */
        "mov %%r12, %%rsi\n"
        "mov $1, %%rax\n"
        "mov $1, %%rdi\n"
        "mov $16, %%rdx\n"
        "syscall\n"
        /* exit(0) — terminates the thread; kernel does CLEARTID + FUTEX_WAKE */
        "mov $60, %%rax\n"            /* SYS_exit */
        "xor %%rdi, %%rdi\n"          /* status = 0 */
        "syscall\n"
        /* Should never reach here; if we do, halt-loop */
        "1: hlt\n"
        "jmp 1b\n"
        "2:\n"
        : "=a"(ret)
        : "r"((long)(uintptr_t)&args),
          "r"((long)sizeof(args)),
          "r"((long)(uintptr_t)child_msg)
        : "rdi", "rsi", "rdx", "rcx", "r11", "r12", "memory"
    );
    if (ret < 0) {
        const char e[] = "[clone_test] clone3 FAILED\n";
        syscall(SYS_write, 1, e, sizeof(e) - 1);
        return 2;
    }
    /* Suppress unused warning for child_entry (kept for documentation). */
    (void)child_entry;
    (void)child_msg;

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
