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
double atof(const char *s);
int   abs(int x);

/* Random. */
void srand(unsigned int seed);
int  rand(void);
int  rand_r(unsigned int *seedp);
int  getrandom(void *buf, unsigned long buflen, unsigned int flags);

long          strtol(const char *s, char **endptr, int base);
unsigned long strtoul(const char *s, char **endptr, int base);
long long     strtoll(const char *s, char **endptr, int base);
unsigned long long strtoull(const char *s, char **endptr, int base);
double        strtod(const char *s, char **endptr);

/* Environment. */
char *getenv(const char *name);
int   setenv(const char *name, const char *value, int overwrite);
int   unsetenv(const char *name);
int   environ_list(char **buf, int max);

#endif /* STDLIB_H */
