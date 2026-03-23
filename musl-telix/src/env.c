/* Environment variables and cwd for Telix. */
#include <telix/types.h>
#include <string.h>

#define MAX_ENV 64
#define MAX_ENV_LEN 128
#define MAX_CWD 64

static char env_store[MAX_ENV][MAX_ENV_LEN];
static int  env_count = 0;
static char cwd[MAX_CWD] = "/";

char *getenv(const char *name) {
    int nlen = (int)strlen(name);
    for (int i = 0; i < env_count; i++) {
        if (strncmp(env_store[i], name, nlen) == 0 && env_store[i][nlen] == '=')
            return &env_store[i][nlen + 1];
    }
    return NULL;
}

int setenv(const char *name, const char *value, int overwrite) {
    int nlen = (int)strlen(name);
    int vlen = (int)strlen(value);

    /* Check for existing entry. */
    for (int i = 0; i < env_count; i++) {
        if (strncmp(env_store[i], name, nlen) == 0 && env_store[i][nlen] == '=') {
            if (!overwrite) return 0;
            /* Overwrite. */
            if (nlen + 1 + vlen >= MAX_ENV_LEN) return -1;
            strcpy(&env_store[i][nlen + 1], value);
            return 0;
        }
    }

    /* New entry. */
    if (env_count >= MAX_ENV) return -1;
    if (nlen + 1 + vlen >= MAX_ENV_LEN) return -1;
    strcpy(env_store[env_count], name);
    env_store[env_count][nlen] = '=';
    strcpy(&env_store[env_count][nlen + 1], value);
    env_count++;
    return 0;
}

int unsetenv(const char *name) {
    int nlen = (int)strlen(name);
    for (int i = 0; i < env_count; i++) {
        if (strncmp(env_store[i], name, nlen) == 0 && env_store[i][nlen] == '=') {
            /* Shift remaining entries down. */
            for (int j = i; j < env_count - 1; j++)
                memcpy(env_store[j], env_store[j + 1], MAX_ENV_LEN);
            env_count--;
            return 0;
        }
    }
    return 0;
}

/* Get pointer to environment array for iteration.
 * Returns count and fills buf with pointers. */
int environ_list(char **buf, int max) {
    int n = (env_count < max) ? env_count : max;
    for (int i = 0; i < n; i++)
        buf[i] = env_store[i];
    return n;
}

int chdir(const char *path) {
    int len = (int)strlen(path);
    if (len >= MAX_CWD) return -1;

    if (path[0] == '/') {
        /* Absolute path. */
        strcpy(cwd, path);
    } else {
        /* Relative path — append to cwd. */
        int cwdlen = (int)strlen(cwd);
        if (cwdlen + 1 + len >= MAX_CWD) return -1;
        if (cwdlen > 1) { /* not just "/" */
            cwd[cwdlen] = '/';
            strcpy(&cwd[cwdlen + 1], path);
        } else {
            strcpy(&cwd[1], path);
        }
    }

    /* Handle "." and ".." */
    /* Simple: just store the path as given for now. */
    return 0;
}

char *getcwd(char *buf, size_t size) {
    int len = (int)strlen(cwd);
    if ((size_t)(len + 1) > size) return NULL;
    strcpy(buf, cwd);
    return buf;
}
