/* String and memory functions. */
#ifndef STRING_H
#define STRING_H

#include <telix/types.h>

size_t  strlen(const char *s);
int     strcmp(const char *a, const char *b);
int     strncmp(const char *a, const char *b, size_t n);
char   *strcpy(char *dst, const char *src);
char   *strncpy(char *dst, const char *src, size_t n);
char   *strcat(char *dst, const char *src);
char   *strncat(char *dst, const char *src, size_t n);
char   *strchr(const char *s, int c);
char   *strrchr(const char *s, int c);
char   *strstr(const char *haystack, const char *needle);
char   *strdup(const char *s);
char   *strtok(char *str, const char *delim);
char   *strtok_r(char *str, const char *delim, char **saveptr);
char   *strerror(int errnum);
size_t  strspn(const char *s, const char *accept);
size_t  strcspn(const char *s, const char *reject);
char   *strpbrk(const char *s, const char *accept);
char   *strsep(char **stringp, const char *delim);

void   *memcpy(void *dst, const void *src, size_t n);
void   *memmove(void *dst, const void *src, size_t n);
void   *memset(void *s, int c, size_t n);
int     memcmp(const void *a, const void *b, size_t n);
void   *memchr(const void *s, int c, size_t n);

#endif /* STRING_H */
