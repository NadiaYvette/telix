/* Timer functions for Telix — interval timers and timer_create. */
#include <telix/syscall.h>
#include <stdint.h>

#define SYS_TIMER_CREATE_NR 94

typedef int clockid_t;
typedef int timer_t;

#define CLOCK_REALTIME  0
#define CLOCK_MONOTONIC 1
#define SIGALRM 14

struct sigevent {
    int sigev_notify;
    int sigev_signo;
    /* Simplified — only support SIGEV_SIGNAL. */
};

struct itimerspec {
    struct { long tv_sec; long tv_nsec; } it_interval;
    struct { long tv_sec; long tv_nsec; } it_value;
};

struct itimerval {
    struct { long tv_sec; long tv_usec; } it_interval;
    struct { long tv_sec; long tv_usec; } it_value;
};

static int active_timer_id = -1;

int timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid) {
    (void)clockid;
    (void)sevp;
    /* Allocate a simple timer ID. */
    active_timer_id++;
    if (timerid) *timerid = active_timer_id;
    return 0;
}

int timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value,
                  struct itimerspec *old_value) {
    (void)timerid; (void)flags; (void)old_value;
    if (!new_value) return -1;

    uint64_t interval_ns = (uint64_t)new_value->it_value.tv_sec * 1000000000ULL
                         + (uint64_t)new_value->it_value.tv_nsec;

    /* SYS_TIMER_CREATE: a0=signal_num, a1=interval_ns */
    __telix_syscall2(SYS_TIMER_CREATE_NR, SIGALRM, interval_ns);
    return 0;
}

int setitimer(int which, const struct itimerval *val, struct itimerval *old) {
    (void)which; (void)old;
    if (!val) return -1;

    uint64_t interval_ns = (uint64_t)val->it_value.tv_sec * 1000000000ULL
                         + (uint64_t)val->it_value.tv_usec * 1000ULL;

    __telix_syscall2(SYS_TIMER_CREATE_NR, SIGALRM, interval_ns);
    return 0;
}
