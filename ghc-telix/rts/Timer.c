/* GHC RTS shim: Timer for Telix.
 *
 * Uses SYS_TIMER_CREATE (Phase 76) to deliver periodic SIGALRM
 * for GHC's context switch / GC tick.
 */
#include <telix/syscall.h>
#include <stdint.h>

#define GHC_TICK_INTERVAL_NS (10 * 1000 * 1000)  /* 10 ms */

static int timer_active = 0;

void initTimer(void) {
    if (timer_active) return;
    /* SYS_TIMER_CREATE: a0=signal_num (SIGALRM=14), a1=interval_ns */
    __telix_syscall2(SYS_TIMER_CREATE, 14, GHC_TICK_INTERVAL_NS);
    timer_active = 1;
}

void exitTimer(void) {
    if (!timer_active) return;
    /* Disable timer by setting interval to 0. */
    __telix_syscall2(SYS_TIMER_CREATE, 14, 0);
    timer_active = 0;
}

/* Called by GHC RTS to get tick interval in microseconds. */
int getTickInterval(void) {
    return GHC_TICK_INTERVAL_NS / 1000;
}
