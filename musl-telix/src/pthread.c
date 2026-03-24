/* POSIX threads for Telix — built on SYS_THREAD_CREATE + futex. */
#include <pthread.h>
#include <telix/syscall.h>
#include <string.h>

#define EBUSY  16
#define EINVAL 22
#define EAGAIN 11
#define ENOMEM 12

/* Thread trampoline: called by new thread, sets up TLS then runs user func. */
struct thread_arg {
    void *(*start)(void *);
    void *arg;
    uint64_t stack_base;
    uint64_t stack_pages;
};

static struct thread_arg thread_args[64];
static volatile int thread_arg_lock = 0;

static void spinlock_acquire(volatile int *lock) {
    while (__sync_lock_test_and_set(lock, 1)) {
        while (*lock) __asm__ volatile("" ::: "memory");
    }
}
static void spinlock_release(volatile int *lock) {
    __sync_lock_release(lock);
}

/* Thread entry trampoline. arg = index into thread_args. */
static void thread_trampoline(uint64_t idx) {
    struct thread_arg ta;
    spinlock_acquire(&thread_arg_lock);
    ta = thread_args[idx];
    spinlock_release(&thread_arg_lock);

    void *ret = ta.start(ta.arg);
    /* Exit with return value encoded as exit code. */
    __telix_syscall1(SYS_EXIT, (uint64_t)(uintptr_t)ret);
    __builtin_unreachable();
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {
    (void)attr;

    /* Allocate stack: 4 pages = 256K. */
    uint64_t stack_pages = 4;
    uint64_t stack = __telix_syscall4(SYS_MMAP_ANON, 0, stack_pages, 1, 0);
    if (stack == (uint64_t)-1) return ENOMEM;

    /* Find a free thread_arg slot. */
    spinlock_acquire(&thread_arg_lock);
    int slot = -1;
    for (int i = 0; i < 64; i++) {
        if (thread_args[i].start == 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        spinlock_release(&thread_arg_lock);
        return EAGAIN;
    }
    thread_args[slot].start = start_routine;
    thread_args[slot].arg = arg;
    thread_args[slot].stack_base = stack;
    thread_args[slot].stack_pages = stack_pages;
    spinlock_release(&thread_arg_lock);

    /* SYS_THREAD_CREATE: a0=entry, a1=stack_top, a2=arg, a3=priority */
    uint64_t stack_top = stack + stack_pages * 0x10000;
    uint64_t tid = __telix_syscall4(SYS_THREAD_CREATE,
        (uint64_t)(uintptr_t)thread_trampoline, stack_top,
        (uint64_t)slot, 10);

    if (tid == (uint64_t)-1) {
        spinlock_acquire(&thread_arg_lock);
        thread_args[slot].start = 0;
        spinlock_release(&thread_arg_lock);
        return EAGAIN;
    }

    *thread = tid;
    return 0;
}

int pthread_join(pthread_t thread, void **retval) {
    uint64_t code = __telix_syscall1(SYS_THREAD_JOIN, thread);
    if (retval) *retval = (void *)(uintptr_t)code;
    return 0;
}

pthread_t pthread_self(void) {
    return __telix_syscall0(SYS_THREAD_ID);
}

void pthread_exit(void *retval) {
    __telix_syscall1(SYS_EXIT, (uint64_t)(uintptr_t)retval);
    __builtin_unreachable();
}

/* Mutex — futex-based, 3-state. */
int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    (void)attr;
    mutex->state = 0;
    return 0;
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
    int c;
    /* Try fast path: 0 → 1. */
    if ((c = __sync_val_compare_and_swap(&mutex->state, 0, 1)) == 0)
        return 0;
    /* Slow path: set to 2 (locked + waiters) and futex wait. */
    if (c != 2)
        c = __sync_lock_test_and_set(&mutex->state, 2);
    while (c != 0) {
        __telix_syscall3(SYS_FUTEX_WAIT,
            (uint64_t)(uintptr_t)&mutex->state, 2, 0);
        c = __sync_lock_test_and_set(&mutex->state, 2);
    }
    return 0;
}

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
    if (__sync_val_compare_and_swap(&mutex->state, 0, 1) == 0)
        return 0;
    return EBUSY;
}

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
    if (__sync_fetch_and_sub(&mutex->state, 1) != 1) {
        mutex->state = 0;
        __telix_syscall2(SYS_FUTEX_WAKE,
            (uint64_t)(uintptr_t)&mutex->state, 1);
    }
    return 0;
}

int pthread_mutex_destroy(pthread_mutex_t *mutex) {
    (void)mutex;
    return 0;
}

/* Condition variable — futex on sequence counter. */
int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
    (void)attr;
    cond->seq = 0;
    return 0;
}

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    int seq = cond->seq;
    pthread_mutex_unlock(mutex);
    __telix_syscall3(SYS_FUTEX_WAIT,
        (uint64_t)(uintptr_t)&cond->seq, (uint64_t)seq, 0);
    pthread_mutex_lock(mutex);
    return 0;
}

int pthread_cond_signal(pthread_cond_t *cond) {
    __sync_fetch_and_add(&cond->seq, 1);
    __telix_syscall2(SYS_FUTEX_WAKE,
        (uint64_t)(uintptr_t)&cond->seq, 1);
    return 0;
}

int pthread_cond_broadcast(pthread_cond_t *cond) {
    __sync_fetch_and_add(&cond->seq, 1);
    __telix_syscall2(SYS_FUTEX_WAKE,
        (uint64_t)(uintptr_t)&cond->seq, 0x7FFFFFFF);
    return 0;
}

int pthread_cond_destroy(pthread_cond_t *cond) {
    (void)cond;
    return 0;
}

/* Once. */
int pthread_once(pthread_once_t *once_control, void (*init_routine)(void)) {
    if (__sync_val_compare_and_swap(once_control, 0, 1) == 0) {
        init_routine();
        __sync_synchronize();
        *once_control = 2;
        __telix_syscall2(SYS_FUTEX_WAKE,
            (uint64_t)(uintptr_t)once_control, 0x7FFFFFFF);
    } else {
        while (*once_control != 2) {
            __telix_syscall3(SYS_FUTEX_WAIT,
                (uint64_t)(uintptr_t)once_control, 1, 0);
        }
    }
    return 0;
}

/* Thread-specific data — static array, 32 keys max. */
#define PTHREAD_KEYS_MAX 32
static void (*key_destructors[PTHREAD_KEYS_MAX])(void *);
static volatile int next_key = 0;

/* Per-thread TSD stored at TLS base (simplified: use static for single-process). */
static void *tsd_values[PTHREAD_KEYS_MAX];

int pthread_key_create(pthread_key_t *key, void (*destructor)(void *)) {
    int k = __sync_fetch_and_add(&next_key, 1);
    if (k >= PTHREAD_KEYS_MAX) return EAGAIN;
    key_destructors[k] = destructor;
    *key = (pthread_key_t)k;
    return 0;
}

int pthread_key_delete(pthread_key_t key) {
    if (key >= PTHREAD_KEYS_MAX) return EINVAL;
    key_destructors[key] = 0;
    return 0;
}

void *pthread_getspecific(pthread_key_t key) {
    if (key >= PTHREAD_KEYS_MAX) return 0;
    return tsd_values[key];
}

int pthread_setspecific(pthread_key_t key, const void *value) {
    if (key >= PTHREAD_KEYS_MAX) return EINVAL;
    tsd_values[key] = (void *)value;
    return 0;
}
