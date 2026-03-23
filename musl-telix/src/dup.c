/* dup/dup2/isatty for Telix — pure userspace FD table operations. */
#include <telix/fd.h>
#include <string.h>

int dup(int oldfd) {
    struct telix_fd_entry *src = telix_fd_get(oldfd);
    if (!src) return -1;

    /* Find lowest free FD >= 3. */
    for (int i = 3; i < TELIX_MAX_FDS; i++) {
        struct telix_fd_entry *dst = telix_fd_get(i);
        if (dst && !dst->active) {
            memcpy(dst, src, sizeof(*dst));
            return i;
        }
    }
    return -1;
}

int dup2(int oldfd, int newfd) {
    if (oldfd == newfd) return newfd;
    if (newfd < 0 || newfd >= TELIX_MAX_FDS) return -1;

    struct telix_fd_entry *src = telix_fd_get(oldfd);
    if (!src) return -1;

    struct telix_fd_entry *dst = telix_fd_get(newfd);
    if (!dst) return -1;

    /* Close newfd if it's open (just clear it, don't send IPC). */
    if (dst->active)
        telix_fd_close(newfd);

    /* Copy the entry. */
    memcpy(dst, src, sizeof(*dst));
    return newfd;
}

int isatty(int fd) {
    struct telix_fd_entry *fde = telix_fd_get(fd);
    if (!fde) return 0;
    return (fde->fd_type == FD_TYPE_CONSOLE) ? 1 : 0;
}
