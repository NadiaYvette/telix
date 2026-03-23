/* POSIX-ish unistd.h for Telix. */
#ifndef UNISTD_H
#define UNISTD_H

#include <telix/types.h>

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

pid_t   fork(void);
int     execve(const char *name, char *const argv[], char *const envp[]);
void    _exit(int status);
pid_t   getpid(void);
uid_t   getuid(void);
uid_t   geteuid(void);
gid_t   getgid(void);
gid_t   getegid(void);
int     setuid(uid_t uid);
int     setgid(gid_t gid);
int     dup(int oldfd);
int     dup2(int oldfd, int newfd);
int     chdir(const char *path);
char   *getcwd(char *buf, size_t size);
int     pipe(int pipefd[2]);
unsigned int sleep(unsigned int seconds);
int     isatty(int fd);

ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
int     close(int fd);

#endif /* UNISTD_H */
