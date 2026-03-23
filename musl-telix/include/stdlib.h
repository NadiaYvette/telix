/* Minimal stdlib for Telix. */
#ifndef STDLIB_H
#define STDLIB_H

#include <telix/types.h>

void *malloc(size_t size);
void  free(void *ptr);
void *calloc(size_t nmemb, size_t size);
void  exit(int status);
int   atoi(const char *s);
long  atol(const char *s);
int   abs(int x);

/* Environment. */
char *getenv(const char *name);
int   setenv(const char *name, const char *value, int overwrite);
int   unsetenv(const char *name);
int   environ_list(char **buf, int max);

#endif /* STDLIB_H */
