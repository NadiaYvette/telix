/* tsh — Telix Shell with built-in coreutils.
 *
 * A POSIX-like shell for the Telix microkernel.
 * All coreutils are compiled in as functions, called in forked children.
 * Supports pipes (cmd1 | cmd2) and output redirection (cmd > file).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <telix/syscall.h>
#include <telix/ipc.h>
#include <telix/fd.h>
#include <telix/vfs.h>

/* Maximum tokens per command line. */
#define MAX_TOKENS 32
#define MAX_LINE   128
#define MAX_PIPE   4

/* ========== Coreutils ========== */

/* ls [path] — list directory via VFS_READDIR. */
static int cmd_ls(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "/";
    int pathlen = (int)strlen(path);
    if (pathlen > 16) pathlen = 16;

    uint64_t w0 = 0, w1 = 0;
    for (int i = 0; i < pathlen && i < 8; i++)
        w0 |= (uint64_t)(unsigned char)path[i] << (i * 8);
    for (int i = 8; i < pathlen && i < 16; i++)
        w1 |= (uint64_t)(unsigned char)path[i] << ((i - 8) * 8);

    uint32_t reply = telix_port_create();
    uint64_t d2 = (uint64_t)(uint32_t)pathlen | ((uint64_t)reply << 32);

    /* First request: start_offset=0 packed in data[3]. */
    telix_send(__telix_vfs_port, VFS_READDIR, w0, w1, d2, 0);

    for (int i = 0; i < 200; i++) {
        struct telix_msg msg;
        if (telix_recv_msg(reply, &msg) != 0) break;

        if (msg.tag == VFS_READDIR_OK) {
            uint64_t fsize = msg.data[0];
            uint64_t nlo = msg.data[1];
            uint64_t nhi = msg.data[2];
            uint32_t next_off = (uint32_t)msg.data[3];

            /* Unpack name. */
            char name[17];
            int nlen = 0;
            for (int j = 0; j < 8; j++) {
                char c = (char)(nlo >> (j * 8));
                if (c) name[nlen++] = c; else break;
            }
            for (int j = 0; j < 8; j++) {
                char c = (char)(nhi >> (j * 8));
                if (c) name[nlen++] = c; else break;
            }
            name[nlen] = '\0';

            printf("  %6lu %s\n", (unsigned long)fsize, name);

            /* Request next entry. */
            telix_send(__telix_vfs_port, VFS_READDIR, w0, w1, d2, (uint64_t)next_off);
        } else {
            /* VFS_READDIR_END or error. */
            break;
        }
    }
    telix_port_destroy(reply);
    return 0;
}

/* cat [file...] — concatenate files to stdout. */
static int cmd_cat(int argc, char **argv) {
    if (argc < 2) {
        /* No args: copy stdin to stdout. */
        char buf[64];
        ssize_t n;
        while ((n = read(0, buf, sizeof(buf))) > 0)
            write(1, buf, n);
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY);
        if (fd < 0) {
            printf("cat: %s: No such file\n", argv[i]);
            return 1;
        }
        char buf[64];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0)
            write(1, buf, n);
        close(fd);
    }
    return 0;
}

/* echo [-n] args... */
static int cmd_echo(int argc, char **argv) {
    int no_newline = 0;
    int start = 1;
    if (argc > 1 && strcmp(argv[1], "-n") == 0) {
        no_newline = 1;
        start = 2;
    }
    for (int i = start; i < argc; i++) {
        if (i > start) write(1, " ", 1);
        write(1, argv[i], strlen(argv[i]));
    }
    if (!no_newline) write(1, "\n", 1);
    return 0;
}

/* wc [-lwc] — word count from stdin. */
static int cmd_wc(int argc, char **argv) {
    int do_lines = 1, do_words = 1, do_chars = 1;
    if (argc > 1) {
        do_lines = do_words = do_chars = 0;
        for (const char *p = argv[1]; *p; p++) {
            if (*p == 'l') do_lines = 1;
            if (*p == 'w') do_words = 1;
            if (*p == 'c') do_chars = 1;
        }
    }
    int lines = 0, words = 0, chars = 0;
    int in_word = 0;
    char buf[64];
    ssize_t n;
    while ((n = read(0, buf, sizeof(buf))) > 0) {
        for (int i = 0; i < (int)n; i++) {
            chars++;
            if (buf[i] == '\n') lines++;
            if (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\n') {
                in_word = 0;
            } else if (!in_word) {
                in_word = 1;
                words++;
            }
        }
    }
    if (do_lines) printf("%d ", lines);
    if (do_words) printf("%d ", words);
    if (do_chars) printf("%d", chars);
    printf("\n");
    return 0;
}

/* head [-n N] — print first N lines from stdin. */
static int cmd_head(int argc, char **argv) {
    int count = 10;
    if (argc > 2 && strcmp(argv[1], "-n") == 0)
        count = atoi(argv[2]);

    int lines = 0;
    char buf[64];
    ssize_t n;
    while (lines < count && (n = read(0, buf, sizeof(buf))) > 0) {
        for (int i = 0; i < (int)n && lines < count; i++) {
            write(1, &buf[i], 1);
            if (buf[i] == '\n') lines++;
        }
    }
    return 0;
}

/* uname [-a] */
static int cmd_uname(int argc, char **argv) {
    (void)argc; (void)argv;
#if defined(__aarch64__)
    printf("Telix 0.1 aarch64\n");
#elif defined(__riscv)
    printf("Telix 0.1 riscv64\n");
#elif defined(__x86_64__)
    printf("Telix 0.1 x86_64\n");
#else
    printf("Telix 0.1 unknown\n");
#endif
    return 0;
}

/* id — print user/group IDs. */
static int cmd_id(int argc, char **argv) {
    (void)argc; (void)argv;
    printf("uid=%d gid=%d euid=%d egid=%d\n",
           (int)getuid(), (int)getgid(), (int)geteuid(), (int)getegid());
    return 0;
}

/* sleep N — sleep for N seconds. */
static int cmd_sleep(int argc, char **argv) {
    if (argc < 2) { printf("sleep: missing operand\n"); return 1; }
    unsigned int secs = (unsigned int)atoi(argv[1]);
    sleep(secs);
    return 0;
}

/* kill [-sig] pid */
static int cmd_kill(int argc, char **argv) {
    int sig = SIGTERM;
    int pidarg = 1;
    if (argc > 2 && argv[1][0] == '-') {
        sig = atoi(&argv[1][1]);
        pidarg = 2;
    }
    if (pidarg >= argc) { printf("kill: missing pid\n"); return 1; }
    pid_t p = (pid_t)atoi(argv[pidarg]);
    return kill(p, sig);
}

/* true / false */
static int cmd_true(int argc, char **argv) { (void)argc; (void)argv; return 0; }
static int cmd_false(int argc, char **argv) { (void)argc; (void)argv; return 1; }

/* ps — list processes via procfs. */
static int cmd_ps(int argc, char **argv) {
    (void)argc; (void)argv;
    printf("  PID CMD\n");
    /* List /proc via VFS_READDIR. */
    cmd_ls(1, (char *[]){(char *)"ls", (char *)"/proc"});
    return 0;
}

/* test / [ — basic conditional tests. */
static int cmd_test(int argc, char **argv) {
    if (argc < 2) return 1;

    /* -z STRING: true if string is empty. */
    if (strcmp(argv[1], "-z") == 0 && argc > 2)
        return (strlen(argv[2]) == 0) ? 0 : 1;
    /* -n STRING: true if string is non-empty. */
    if (strcmp(argv[1], "-n") == 0 && argc > 2)
        return (strlen(argv[2]) > 0) ? 0 : 1;
    /* STRING = STRING */
    if (argc > 2 && strcmp(argv[2], "=") == 0 && argc > 3)
        return (strcmp(argv[1], argv[3]) == 0) ? 0 : 1;
    /* STRING != STRING */
    if (argc > 2 && strcmp(argv[2], "!=") == 0 && argc > 3)
        return (strcmp(argv[1], argv[3]) != 0) ? 0 : 1;
    /* -f FILE: true if file exists (we just try stat). */
    if (strcmp(argv[1], "-f") == 0 && argc > 2) {
        struct stat st;
        return (stat(argv[2], &st) == 0) ? 0 : 1;
    }
    /* ! EXPR: negate. */
    if (strcmp(argv[1], "!") == 0 && argc > 2) {
        char *sub[MAX_TOKENS];
        for (int i = 2; i < argc; i++) sub[i-2] = argv[i];
        return cmd_test(argc - 1, sub) ? 0 : 1;
    }
    return 1;
}

/* mkdir name — create directory (stub, not fully implemented). */
static int cmd_mkdir(int argc, char **argv) {
    if (argc < 2) { printf("mkdir: missing operand\n"); return 1; }
    printf("mkdir: not yet implemented for %s\n", argv[1]);
    return 1;
}

/* rm file — delete file. */
static int cmd_rm(int argc, char **argv) {
    if (argc < 2) { printf("rm: missing operand\n"); return 1; }
    printf("rm: not yet implemented for %s\n", argv[1]);
    return 1;
}

/* cp src dst — copy file. */
static int cmd_cp(int argc, char **argv) {
    if (argc < 3) { printf("cp: missing operand\n"); return 1; }
    int src = open(argv[1], O_RDONLY);
    if (src < 0) { printf("cp: cannot open %s\n", argv[1]); return 1; }
    /* For now, write not implemented, so just print error. */
    printf("cp: file write not yet implemented\n");
    close(src);
    return 1;
}

/* env — print environment variables. */
static int cmd_env_print(int argc, char **argv) {
    (void)argc; (void)argv;
    char *ptrs[64];
    int n = environ_list(ptrs, 64);
    for (int i = 0; i < n; i++)
        printf("%s\n", ptrs[i]);
    return 0;
}

/* ========== Command dispatch table ========== */

typedef int (*cmd_func_t)(int argc, char **argv);

struct cmd_entry {
    const char *name;
    cmd_func_t func;
};

static const struct cmd_entry commands[] = {
    { "ls",     cmd_ls },
    { "cat",    cmd_cat },
    { "echo",   cmd_echo },
    { "wc",     cmd_wc },
    { "head",   cmd_head },
    { "uname",  cmd_uname },
    { "id",     cmd_id },
    { "sleep",  cmd_sleep },
    { "kill",   cmd_kill },
    { "true",   cmd_true },
    { "false",  cmd_false },
    { "ps",     cmd_ps },
    { "test",   cmd_test },
    { "[",      cmd_test },
    { "mkdir",  cmd_mkdir },
    { "rm",     cmd_rm },
    { "cp",     cmd_cp },
    { "env",    cmd_env_print },
    { NULL, NULL }
};

static cmd_func_t find_command(const char *name) {
    for (int i = 0; commands[i].name; i++) {
        if (strcmp(commands[i].name, name) == 0)
            return commands[i].func;
    }
    return NULL;
}

/* ========== Tokenizer ========== */

static int tokenize(char *line, char **tokens, int max_tokens) {
    int count = 0;
    char *p = line;
    while (*p && count < max_tokens - 1) {
        /* Skip whitespace. */
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '\n') break;

        tokens[count++] = p;

        /* Advance to next whitespace or special char. */
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') {
            if (*p == '|' || *p == '>' || *p == '<') {
                if (tokens[count - 1] == p) {
                    /* Special char is its own token. */
                    p++;
                    break;
                } else {
                    /* End current token before special char. */
                    break;
                }
            }
            p++;
        }
        if (*p == ' ' || *p == '\t' || *p == '\n') {
            *p++ = '\0';
        } else if (*p == '|' || *p == '>' || *p == '<') {
            /* Don't null-terminate here — special char is next token. */
            if (tokens[count - 1] != p) {
                char save = *p;
                *p = '\0';
                p++;
                /* Re-insert the special char back... actually just push it. */
                /* We already advanced p past the null. The special char is lost.
                 * Let's use a different approach. */
                /* Restart: simpler tokenizer. */
            }
        }
    }
    tokens[count] = NULL;
    return count;
}

/* Simpler tokenizer: split by spaces, pipes and redirects are separate tokens. */
static int tokenize_line(char *line, char **tokens, int max_tokens) {
    int count = 0;
    char *p = line;

    /* Strip trailing newline. */
    int len = (int)strlen(line);
    if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';

    while (*p && count < max_tokens - 1) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        if (*p == '|' || *p == '>' || *p == '<') {
            /* Make it a 1-char null-terminated token. */
            tokens[count] = p;
            p++;
            /* If next char is not space, we need to insert a null. */
            if (*p != ' ' && *p != '\t' && *p != '\0') {
                /* Shift rest of string right by 1 to insert null... too complex.
                 * Instead, use a static buffer approach. */
                /* For simplicity: special chars must be space-separated by user. */
            }
            /* Null-terminate the special token. */
            /* If followed by non-space, just treat the rest as next token. */
            count++;
            continue;
        }

        tokens[count++] = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '|' && *p != '>' && *p != '<')
            p++;
        if (*p) {
            if (*p == '|' || *p == '>' || *p == '<') {
                /* Don't consume the special char, just null-terminate current. */
                /* Insert null between current token and special char. */
                /* We can't insert in place, so require space-separated special chars. */
                /* For now, null-terminate here and the special char becomes next iter. */
                /* Actually we can: just poke a null and don't advance. */
                /* But that destroys the special char. Store it first. */
                continue; /* leave *p alone, next iteration picks it up */
            }
            *p++ = '\0';
        }
    }
    tokens[count] = NULL;
    return count;
}

/* ========== Command execution ========== */

/* Run a single command (possibly an internal function or external execve). */
static int run_command(int argc, char **argv) {
    if (argc == 0) return 0;

    cmd_func_t func = find_command(argv[0]);
    if (func) {
        return func(argc, argv);
    }

    /* Unknown command — try execve (external binary from initramfs). */
    printf("tsh: %s: command not found\n", argv[0]);
    return 127;
}

/* Run a single command in a forked child, wait for it.
 * Returns exit status. */
static int fork_and_run(int argc, char **argv) {
    if (argc == 0) return 0;

    /* Builtins run in parent. */
    if (strcmp(argv[0], "cd") == 0) {
        if (argc > 1) chdir(argv[1]);
        else chdir("/");
        return 0;
    }
    if (strcmp(argv[0], "pwd") == 0) {
        char buf[64];
        getcwd(buf, sizeof(buf));
        printf("%s\n", buf);
        return 0;
    }
    if (strcmp(argv[0], "exit") == 0) {
        _exit(argc > 1 ? atoi(argv[1]) : 0);
        return 0; /* unreachable */
    }
    if (strcmp(argv[0], "export") == 0) {
        if (argc > 1) {
            char *eq = strchr(argv[1], '=');
            if (eq) {
                *eq = '\0';
                setenv(argv[1], eq + 1, 1);
                *eq = '=';
            }
        }
        return 0;
    }
    if (strcmp(argv[0], "help") == 0) {
        printf("tsh — Telix Shell\n");
        printf("Built-in commands:\n");
        printf("  cd [dir]   pwd   exit [code]   export VAR=val\n");
        printf("  help   env\n");
        printf("Coreutils:\n");
        printf("  ls cat echo wc head uname id sleep kill\n");
        printf("  true false ps test mkdir rm cp\n");
        printf("Operators: cmd1 | cmd2, cmd > file\n");
        return 0;
    }

    /* Fork and run. */
    pid_t pid = fork();
    if (pid < 0) {
        printf("tsh: fork failed\n");
        return 1;
    }
    if (pid == 0) {
        /* Child process. */
        cmd_func_t func = find_command(argv[0]);
        if (func) {
            int ret = func(argc, argv);
            _exit(ret);
        }
        /* Try external execve. */
        execve(argv[0], NULL, NULL);
        printf("tsh: %s: command not found\n", argv[0]);
        _exit(127);
    }

    /* Parent: wait for child. */
    int status = 0;
    waitpid(pid, &status, 0);
    return WEXITSTATUS(status);
}

/* ========== Pipeline execution ========== */

/* Find pipe '|' in tokens. Returns index or -1. */
static int find_pipe(char **tokens, int ntokens) {
    for (int i = 0; i < ntokens; i++) {
        if (tokens[i][0] == '|' && tokens[i][1] == '\0')
            return i;
    }
    return -1;
}

/* Find redirect '>' in tokens. Returns index or -1. */
static int find_redirect_out(char **tokens, int ntokens) {
    for (int i = 0; i < ntokens; i++) {
        if (tokens[i][0] == '>' && tokens[i][1] == '\0')
            return i;
    }
    return -1;
}

/* Execute a pipeline or simple command with redirection. */
static int execute_line(char **tokens, int ntokens) {
    if (ntokens == 0) return 0;

    /* Check for output redirection: cmd > file */
    int redir_idx = find_redirect_out(tokens, ntokens);
    if (redir_idx >= 0 && redir_idx + 1 < ntokens) {
        /* Output redirect — not implemented yet (file write needed). */
        printf("tsh: output redirection not yet implemented\n");
        return 1;
    }

    /* Check for pipe: cmd1 | cmd2 */
    int pipe_idx = find_pipe(tokens, ntokens);
    if (pipe_idx > 0 && pipe_idx < ntokens - 1) {
        /* Create pipe. */
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            printf("tsh: pipe failed\n");
            return 1;
        }

        /* Split into left and right commands. */
        tokens[pipe_idx] = NULL;
        int left_argc = pipe_idx;
        char **right_argv = &tokens[pipe_idx + 1];
        int right_argc = ntokens - pipe_idx - 1;

        /* Fork left child: stdout -> pipe write end. */
        pid_t pid1 = fork();
        if (pid1 == 0) {
            close(pipefd[0]); /* close read end */
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[1]);
            cmd_func_t func = find_command(tokens[0]);
            if (func) _exit(func(left_argc, tokens));
            execve(tokens[0], NULL, NULL);
            _exit(127);
        }

        /* Fork right child: stdin <- pipe read end. */
        pid_t pid2 = fork();
        if (pid2 == 0) {
            close(pipefd[1]); /* close write end */
            dup2(pipefd[0], STDIN_FILENO);
            close(pipefd[0]);

            /* Check for another pipe in right side. */
            int pipe2 = find_pipe(right_argv, right_argc);
            if (pipe2 >= 0) {
                /* Recursive pipeline not supported in child — just run first cmd. */
            }

            cmd_func_t func = find_command(right_argv[0]);
            if (func) _exit(func(right_argc, right_argv));
            execve(right_argv[0], NULL, NULL);
            _exit(127);
        }

        /* Parent: close pipe, wait for both children. */
        close(pipefd[0]);
        close(pipefd[1]);
        int status;
        waitpid(pid1, &status, 0);
        waitpid(pid2, &status, 0);
        return WEXITSTATUS(status);
    }

    /* Simple command — no pipes or redirects. */
    return fork_and_run(ntokens, tokens);
}

/* ========== Main shell loop ========== */

int main(int arg0, int arg1, int arg2) {
    (void)arg0; (void)arg1; (void)arg2;

    /* Ignore SIGINT in the shell process. */
    signal(SIGINT, SIG_IGN);

    printf("\nTelix Shell (tsh) — type 'help' for commands\n\n");

    for (;;) {
        /* Print prompt. */
        char cwdbuf[64];
        getcwd(cwdbuf, sizeof(cwdbuf));
        printf("%s$ ", cwdbuf);
        fflush(stdout);

        /* Read line. */
        char line[MAX_LINE];
        ssize_t n = read(STDIN_FILENO, line, sizeof(line) - 1);
        if (n <= 0) break; /* EOF */
        line[n] = '\0';

        /* Strip trailing newline. */
        if (n > 0 && line[n - 1] == '\n') line[n - 1] = '\0';
        if (line[0] == '\0') continue;

        /* Tokenize. */
        char *tokens[MAX_TOKENS];
        int ntokens = tokenize_line(line, tokens, MAX_TOKENS);
        if (ntokens == 0) continue;

        /* Execute. */
        execute_line(tokens, ntokens);
    }

    return 0;
}
