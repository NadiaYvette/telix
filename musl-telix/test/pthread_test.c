/* Test: pthreads (Phase 74).
 * 4 threads increment mutex-protected counter 1000x each.
 */
#include <pthread.h>

extern long write(int fd, const void *buf, unsigned long count);
extern void _exit(int status) __attribute__((noreturn));

static void puts_s(const char *s) {
    int n = 0;
    while (s[n]) n++;
    write(1, s, n);
}

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static volatile int counter = 0;

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 1000; i++) {
        pthread_mutex_lock(&mtx);
        counter++;
        pthread_mutex_unlock(&mtx);
    }
    return (void *)0;
}

int main(int argc, char **argv, char **envp) {
    (void)argc; (void)argv; (void)envp;

    pthread_t threads[4];
    for (int i = 0; i < 4; i++) {
        if (pthread_create(&threads[i], 0, worker, 0) != 0) {
            puts_s("pthread_test: create FAIL\n");
            _exit(1);
        }
    }

    for (int i = 0; i < 4; i++) {
        pthread_join(threads[i], 0);
    }

    if (counter == 4000) {
        puts_s("pthread_test: PASSED\n");
        _exit(0);
    } else {
        puts_s("pthread_test: counter mismatch FAIL\n");
        _exit(1);
    }
}
