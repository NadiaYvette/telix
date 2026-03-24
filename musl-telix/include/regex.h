#ifndef REGEX_H
#define REGEX_H

#include <telix/types.h>

/* Compile flags. */
#define REG_EXTENDED 1
#define REG_ICASE    2
#define REG_NOSUB    4
#define REG_NEWLINE  8

/* Exec flags. */
#define REG_NOTBOL   1
#define REG_NOTEOL   2

/* Error codes. */
#define REG_OK       0
#define REG_NOMATCH  1
#define REG_BADPAT   2
#define REG_ESPACE   12

typedef struct {
    char  *pattern;   /* compiled (stored) pattern string */
    int    cflags;    /* compile flags                    */
    size_t re_nsub;   /* number of parenthesised sub-expressions */
} regex_t;

typedef struct {
    int rm_so;  /* byte offset of start of match */
    int rm_eo;  /* byte offset past end of match */
} regmatch_t;

int  regcomp(regex_t *preg, const char *pattern, int cflags);
int  regexec(const regex_t *preg, const char *string,
             size_t nmatch, regmatch_t pmatch[], int eflags);
void regfree(regex_t *preg);
size_t regerror(int errcode, const regex_t *preg,
                char *errbuf, size_t errbuf_size);

#endif /* REGEX_H */
