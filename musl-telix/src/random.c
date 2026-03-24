/* random.c — PRNG and getrandom stub for Telix. */

#include <stdlib.h>
#include <telix/syscall.h>

#define SYS_GETRANDOM 96

static unsigned long _rand_state = 1;

int getrandom(void *buf, unsigned long buflen, unsigned int flags) {
    (void)flags;
    return (int)__telix_syscall3(SYS_GETRANDOM, (uint64_t)buf, buflen, 0);
}

void srand(unsigned int seed) {
    _rand_state = seed;
}

int rand(void) {
    _rand_state = _rand_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (int)((_rand_state >> 33) & 0x7fffffff);
}

int rand_r(unsigned int *seedp) {
    unsigned long s = *seedp;
    s = s * 6364136223846793005ULL + 1442695040888963407ULL;
    *seedp = (unsigned int)s;
    return (int)((s >> 33) & 0x7fffffff);
}
