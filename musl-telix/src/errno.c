#include <errno.h>

static int __errno_val;

int *__telix_errno_location(void) {
    return &__errno_val;
}

/* Alias for code that references the glibc name directly. */
int *__errno_location(void) {
    return &__errno_val;
}
