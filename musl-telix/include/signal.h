/* Signal handling for Telix. */
#ifndef SIGNAL_H
#define SIGNAL_H

#include <telix/types.h>

#define SIGHUP    1
#define SIGINT    2
#define SIGQUIT   3
#define SIGKILL   9
#define SIGTERM  15
#define SIGCHLD  17
#define SIGCONT  18
#define SIGSTOP  19
#define SIGTSTP  20

typedef void (*sighandler_t)(int);

#define SIG_DFL ((sighandler_t)0)
#define SIG_IGN ((sighandler_t)1)

sighandler_t signal(int sig, sighandler_t handler);
int kill(pid_t pid, int sig);

#endif /* SIGNAL_H */
