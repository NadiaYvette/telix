/* GHC RTS shim: OS thread management for Telix.
 *
 * Maps GHC's createOSThread / joinOSThread to pthreads (Phase 74).
 */
#include <pthread.h>
#include <stdint.h>

typedef pthread_t OSThreadId;
typedef pthread_mutex_t Mutex;
typedef pthread_cond_t Condition;

int createOSThread(OSThreadId *tid, void *(*start)(void *), void *param) {
    return pthread_create(tid, 0, start, param);
}

int joinOSThread(OSThreadId tid) {
    return pthread_join(tid, 0);
}

OSThreadId osThreadId(void) {
    return pthread_self();
}

void initMutex(Mutex *m) {
    pthread_mutex_init(m, 0);
}

void closeMutex(Mutex *m) {
    pthread_mutex_destroy(m);
}

void acquireLock(Mutex *m) {
    pthread_mutex_lock(m);
}

void releaseLock(Mutex *m) {
    pthread_mutex_unlock(m);
}

void initCondition(Condition *c) {
    pthread_cond_init(c, 0);
}

void closeCondition(Condition *c) {
    pthread_cond_destroy(c);
}

void signalCondition(Condition *c) {
    pthread_cond_signal(c);
}

void broadcastCondition(Condition *c) {
    pthread_cond_broadcast(c);
}

void waitCondition(Condition *c, Mutex *m) {
    pthread_cond_wait(c, m);
}
