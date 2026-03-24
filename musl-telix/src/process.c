/* Process control functions for Telix. */
#include <telix/syscall.h>
#include <telix/types.h>
#include <string.h>

pid_t fork(void) {
    uint64_t result = __telix_syscall0(SYS_FORK);
    /* Kernel returns: child TID to parent, 0 to child, u64::MAX on error. */
    if (result == (uint64_t)-1)
        return -1;
    return (pid_t)result;
}

int execve(const char *name, char *const argv[], char *const envp[]) {
    /* Telix execve: a0=name_ptr, a1=name_len, a2=argv, a3=envp. */
    size_t len = strlen(name);
    uint64_t result = __telix_syscall6(SYS_EXECVE, (uint64_t)name, len,
                                        (uint64_t)argv, (uint64_t)envp, 0, 0);
    /* execve only returns on failure. */
    (void)result;
    return -1;
}

pid_t waitpid(pid_t pid, int *status, int options) {
    /* SYS_WAITPID(child_tid) returns exit code or u64::MAX if not exited. */
    if (options & 1 /* WNOHANG */) {
        uint64_t result = __telix_syscall1(SYS_WAITPID, (uint64_t)(uint32_t)pid);
        if (result == (uint64_t)-1)
            return 0; /* not exited yet */
        if (status) *status = (int)(result << 8);
        return pid;
    }

    /* Blocking wait: poll with yield. */
    for (;;) {
        uint64_t result = __telix_syscall1(SYS_WAITPID, (uint64_t)(uint32_t)pid);
        if (result != (uint64_t)-1) {
            if (status) *status = (int)(result << 8);
            return pid;
        }
        __telix_syscall0(SYS_YIELD);
    }
}

pid_t getpid(void) {
    return (pid_t)__telix_syscall0(SYS_GETPID);
}

uid_t getuid(void) {
    return (uid_t)__telix_syscall0(SYS_GETUID);
}

uid_t geteuid(void) {
    return (uid_t)__telix_syscall0(SYS_GETEUID);
}

gid_t getgid(void) {
    return (gid_t)__telix_syscall0(SYS_GETGID);
}

gid_t getegid(void) {
    return (gid_t)__telix_syscall0(SYS_GETEGID);
}

int setuid(uid_t uid) {
    uint64_t r = __telix_syscall1(SYS_SETUID, uid);
    return (r == 0) ? 0 : -1;
}

int setgid(gid_t gid) {
    uint64_t r = __telix_syscall1(SYS_SETGID, gid);
    return (r == 0) ? 0 : -1;
}

unsigned int sleep(unsigned int seconds) {
    /* SYS_NANOSLEEP(seconds, nanoseconds) */
    __telix_syscall2(SYS_NANOSLEEP, seconds, 0);
    return 0;
}

int kill(pid_t pid, int sig) {
    uint64_t r = __telix_syscall2(SYS_KILL_SIG, (uint64_t)(uint32_t)pid, (uint64_t)sig);
    return (r == 0) ? 0 : -1;
}
