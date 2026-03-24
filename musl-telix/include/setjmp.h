#ifndef SETJMP_H
#define SETJMP_H

typedef unsigned long jmp_buf[24];
typedef unsigned long sigjmp_buf[24];

int  setjmp(jmp_buf env);
void longjmp(jmp_buf env, int val) __attribute__((noreturn));

#define sigsetjmp(env, savesigs)   setjmp(env)
#define siglongjmp(env, val)       longjmp(env, val)

#endif
