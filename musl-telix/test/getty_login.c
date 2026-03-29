/* getty_login — combined getty + login for Telix.
 *
 * Prints a login prompt, reads username/password, validates against
 * /etc/passwd, sets uid/gid, and execs the user's shell (tsh).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <telix/syscall.h>
#include <telix/vfs.h>

/* Parse /etc/passwd and find a matching user.
 * Format: user:pass:uid:gid:gecos:home:shell
 * Returns 1 on match, fills out uid/gid. */
static int check_passwd(const char *user, const char *pass,
                         uid_t *uid_out, gid_t *gid_out) {
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) {
        /* No passwd file — allow root with no password. */
        if (strcmp(user, "root") == 0) {
            *uid_out = 0;
            *gid_out = 0;
            return 1;
        }
        return 0;
    }

    char buf[256];
    ssize_t total = 0;
    ssize_t n;
    while ((n = read(fd, buf + total, sizeof(buf) - 1 - total)) > 0)
        total += n;
    buf[total] = '\0';
    close(fd);


    /* Parse lines. */
    char *line = buf;
    while (*line) {
        /* Find end of line. */
        char *eol = strchr(line, '\n');
        if (eol) *eol = '\0';

        /* Split by ':'. */
        char *fields[7];
        int nf = 0;
        char *p = line;
        while (nf < 7) {
            fields[nf++] = p;
            char *colon = strchr(p, ':');
            if (colon) { *colon = '\0'; p = colon + 1; }
            else break;
        }

        if (nf >= 4 && strcmp(fields[0], user) == 0) {
            /* Check password: empty field = no password required. */
            if (fields[1][0] == '\0' || strcmp(fields[1], pass) == 0) {
                *uid_out = (uid_t)atoi(fields[2]);
                *gid_out = (gid_t)atoi(fields[3]);
                return 1;
            }
        }

        if (eol) line = eol + 1;
        else break;
    }
    return 0;
}

int main(int arg0, int arg1, int arg2) {
    (void)arg0; (void)arg1; (void)arg2;

    printf("\nTelix 0.1\n");

    for (;;) {
        /* Read username. */
        printf("\nlogin: ");
        fflush(stdout);
        char user[32];
        ssize_t n = read(STDIN_FILENO, user, sizeof(user) - 1);
        if (n <= 0) continue;
        user[n] = '\0';
        /* Strip trailing newline. */
        if (n > 0 && user[n - 1] == '\n') user[n - 1] = '\0';
        if (user[0] == '\0') continue;

        /* Read password. */
        printf("password: ");
        fflush(stdout);
        char pass[32];
        n = read(STDIN_FILENO, pass, sizeof(pass) - 1);
        if (n <= 0) { pass[0] = '\0'; n = 0; }
        else { pass[n] = '\0'; if (pass[n-1] == '\n') pass[n-1] = '\0'; }

        /* Check credentials. */
        uid_t uid;
        gid_t gid;
        if (check_passwd(user, pass, &uid, &gid)) {
            printf("Welcome, %s!\n", user);

            /* Set credentials. */
            setuid(uid);
            setgid(gid);

            /* Set environment. */
            setenv("USER", user, 1);
            setenv("HOME", "/", 1);
            setenv("SHELL", "/tsh", 1);

            /* Exec the shell. */
            {
                const char *m = "[getty] execve(tsh)...\n";
                __telix_syscall2(14, (uint64_t)(unsigned long)m, 22);
            }
            execve("tsh", NULL, NULL);

            /* If execve fails, print error and loop. */
            printf("login: failed to exec tsh\n");
        } else {
            printf("Login incorrect\n");
        }
    }

    return 0;
}
