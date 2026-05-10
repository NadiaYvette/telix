/* Phase 176 test: glibc pthread_create + pthread_join + printf in child.
 *
 * Tier-2 milestone: prove glibc's full pthread machinery works under
 * linux_srv.  Exercises:
 *   - clone(CLONE_VM|CLONE_THREAD|CLONE_SETTLS|...)
 *   - set_tid_address (per-thread)
 *   - set_robust_list
 *   - futex(FUTEX_WAIT/WAKE) on the thread descriptor's tid for join
 *   - thread-local TLS via FS-base
 *
 * Statically linked so we don't drag in ld.so dyn-link concerns.  We use
 * a small printf instead of write() so glibc has to set up at least a
 * minimal stdio path from the child thread (cross-thread lock).
 */
#include <stdio.h>
#include <pthread.h>

static void *thread_main(void *arg)
{
    long n = (long)arg;
    printf("[pthread_hello] child thread n=%ld\n", n);
    return (void *)(n + 1);
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    pthread_t t;
    void *rv = (void *)0;

    if (pthread_create(&t, NULL, thread_main, (void *)41) != 0) {
        printf("[pthread_hello] pthread_create FAILED\n");
        return 2;
    }
    if (pthread_join(t, &rv) != 0) {
        printf("[pthread_hello] pthread_join FAILED\n");
        return 3;
    }
    printf("[pthread_hello] join rv=%ld\n", (long)rv);
    /* Exit code 42 = success signal observed by the Phase 176 driver. */
    return (long)rv == 42 ? 42 : 4;
}
