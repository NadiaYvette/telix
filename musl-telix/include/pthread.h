#ifndef _PTHREAD_H
#define _PTHREAD_H

#include <stdint.h>
#include <stddef.h>

typedef uint64_t pthread_t;
typedef int pthread_attr_t;
typedef int pthread_mutexattr_t;
typedef int pthread_condattr_t;

typedef struct {
    volatile int state;  /* 0=unlocked, 1=locked, 2=locked+waiters */
} pthread_mutex_t;

#define PTHREAD_MUTEX_INITIALIZER {0}

typedef struct {
    volatile int seq;
} pthread_cond_t;

#define PTHREAD_COND_INITIALIZER {0}

typedef volatile int pthread_once_t;
#define PTHREAD_ONCE_INIT 0

typedef unsigned int pthread_key_t;

/* Thread management. */
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg);
int pthread_join(pthread_t thread, void **retval);
pthread_t pthread_self(void);
void pthread_exit(void *retval) __attribute__((noreturn));

/* Mutex. */
int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_destroy(pthread_mutex_t *mutex);

/* Condition variable. */
int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr);
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int pthread_cond_signal(pthread_cond_t *cond);
int pthread_cond_broadcast(pthread_cond_t *cond);
int pthread_cond_destroy(pthread_cond_t *cond);

/* Once. */
int pthread_once(pthread_once_t *once_control, void (*init_routine)(void));

/* Thread-specific data. */
int pthread_key_create(pthread_key_t *key, void (*destructor)(void *));
int pthread_key_delete(pthread_key_t key);
void *pthread_getspecific(pthread_key_t key);
int pthread_setspecific(pthread_key_t key, const void *value);

#endif /* _PTHREAD_H */
