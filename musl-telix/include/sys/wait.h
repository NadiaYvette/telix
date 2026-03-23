/* POSIX wait.h for Telix. */
#ifndef SYS_WAIT_H
#define SYS_WAIT_H

#include <telix/types.h>

#define WNOHANG 1

/* Exit status encoding: status = (exit_code << 8) | 0.
 * Matches what the kernel stores. */
#define WIFEXITED(s)    (((s) & 0xFF) == 0)
#define WEXITSTATUS(s)  (((s) >> 8) & 0xFF)
#define WIFSIGNALED(s)  (((s) & 0x7F) != 0)
#define WTERMSIG(s)     ((s) & 0x7F)

pid_t waitpid(pid_t pid, int *status, int options);

#endif /* SYS_WAIT_H */
