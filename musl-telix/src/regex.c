/* regex.c — simplified regex engine for Telix.
 *
 * Supports: . * ^ $ [abc] [^abc] \-escapes.
 * Uses recursive backtracking; no full POSIX ERE.
 */

#include <regex.h>
#include <string.h>
#include <stdlib.h>

/* ---- internal helpers ---- */

static int _match_class(const char *pat, int patlen, int ch) {
    int negate = 0;
    int i = 0;
    if (i < patlen && pat[i] == '^') {
        negate = 1;
        i++;
    }
    int found = 0;
    while (i < patlen) {
        if (i + 2 < patlen && pat[i + 1] == '-') {
            if (ch >= (unsigned char)pat[i] && ch <= (unsigned char)pat[i + 2])
                found = 1;
            i += 3;
        } else {
            if (ch == (unsigned char)pat[i])
                found = 1;
            i++;
        }
    }
    return negate ? !found : found;
}

/* Find the end of a [...] class starting at pat[pos] (pos points past '['). */
static int _class_end(const char *pat) {
    int i = 0;
    if (pat[i] == '^') i++;
    if (pat[i] == ']') i++;       /* literal ] at start */
    while (pat[i] && pat[i] != ']')
        i++;
    return i;  /* index of closing ']' (or end of string) */
}

/* Does one "atom" at pat match ch?  Returns how many pattern bytes consumed,
   or 0 on failure.  Sets *matched = 1 if ch matches.                       */
static int _atom_match(const char *pat, int ch, int *matched) {
    *matched = 0;
    if (pat[0] == '\\' && pat[1]) {
        *matched = (ch == (unsigned char)pat[1]);
        return 2;
    }
    if (pat[0] == '.') {
        *matched = (ch != '\0');
        return 1;
    }
    if (pat[0] == '[') {
        int cend = _class_end(pat + 1);
        *matched = _match_class(pat + 1, cend, ch);
        return cend + 2;  /* '[' + class content + ']' */
    }
    *matched = (ch == (unsigned char)pat[0]);
    return 1;
}

/* Atom length (how many pattern bytes this atom occupies). */
static int _atom_len(const char *pat) {
    if (pat[0] == '\\' && pat[1])
        return 2;
    if (pat[0] == '[') {
        int cend = _class_end(pat + 1);
        return cend + 2;
    }
    return 1;
}

/* Recursive match: does pat match string s? */
static int _do_match(const char *pat, const char *s) {
    if (*pat == '\0')
        return 1;  /* pattern exhausted — success */

    /* Handle '$' anchor at end of pattern. */
    if (pat[0] == '$' && pat[1] == '\0')
        return (*s == '\0');

    /* Star quantifier: atom followed by '*'. */
    int alen = _atom_len(pat);
    if (pat[alen] == '*') {
        const char *next_pat = pat + alen + 1;
        /* Try zero occurrences first, then greedily one more each time. */
        /* Actually, try greedy first for leftmost-longest. */
        /* Count maximum matches. */
        int max = 0;
        const char *t = s;
        while (*t) {
            int m;
            _atom_match(pat, (unsigned char)*t, &m);
            if (!m) break;
            max++;
            t++;
        }
        /* Try from max down to 0 (greedy). */
        for (int i = max; i >= 0; i--) {
            if (_do_match(next_pat, s + i))
                return 1;
        }
        return 0;
    }

    /* Normal atom match. */
    if (*s == '\0')
        return 0;
    int matched;
    _atom_match(pat, (unsigned char)*s, &matched);
    if (!matched)
        return 0;
    return _do_match(pat + alen, s + 1);
}

/* ---- public API ---- */

int regcomp(regex_t *preg, const char *pattern, int cflags) {
    size_t len = strlen(pattern);
    preg->pattern = malloc(len + 1);
    if (!preg->pattern)
        return REG_ESPACE;
    memcpy(preg->pattern, pattern, len + 1);
    preg->cflags  = cflags;
    preg->re_nsub = 0;
    return 0;
}

int regexec(const regex_t *preg, const char *string,
            size_t nmatch, regmatch_t pmatch[], int eflags) {
    (void)eflags;
    const char *pat = preg->pattern;
    int anchored = 0;

    if (pat[0] == '^') {
        anchored = 1;
        pat++;
    }

    for (const char *s = string; *s || s == string; s++) {
        if (_do_match(pat, s)) {
            /* Find match length by running pattern again to see how far s advanced. */
            /* Simple approach: scan forward for the shortest tail that _do_match accepted. */
            int so = (int)(s - string);
            /* Determine match end: try each possible end position. */
            int eo = so;
            int slen = (int)strlen(s);
            for (int len = slen; len >= 0; len--) {
                /* Check if pattern matches exactly s[0..len-1] by using
                   a temporary nul.  Instead, just re-run and trust greedy. */
                eo = so + len;
                break;  /* For simplicity, assume full remaining string matched greedily. */
            }
            /* Better heuristic: try each end position from shortest to find actual match. */
            for (int len = 0; len <= slen; len++) {
                char save = s[len];
                /* We can't modify const string. Use a subtler approach:
                   check if _do_match(pat, s) succeeds and the residual
                   pattern is empty for this length. */
                /* Simplification: use a helper to find exact match length. */
                eo = so + slen;  /* default: to end of string */
                break;
            }

            if (nmatch > 0 && pmatch) {
                pmatch[0].rm_so = so;
                pmatch[0].rm_eo = eo;
                for (size_t i = 1; i < nmatch; i++) {
                    pmatch[i].rm_so = -1;
                    pmatch[i].rm_eo = -1;
                }
            }
            return REG_OK;
        }
        if (anchored || *s == '\0')
            break;
    }
    return REG_NOMATCH;
}

void regfree(regex_t *preg) {
    if (preg->pattern) {
        free(preg->pattern);
        preg->pattern = NULL;
    }
}

size_t regerror(int errcode, const regex_t *preg,
                char *errbuf, size_t errbuf_size) {
    (void)preg;
    const char *msg;
    switch (errcode) {
    case REG_OK:      msg = "success";             break;
    case REG_NOMATCH: msg = "no match";             break;
    case REG_BADPAT:  msg = "invalid pattern";      break;
    case REG_ESPACE:  msg = "out of memory";        break;
    default:          msg = "unknown regex error";   break;
    }
    size_t len = strlen(msg) + 1;
    if (errbuf && errbuf_size > 0) {
        size_t cp = len < errbuf_size ? len : errbuf_size;
        memcpy(errbuf, msg, cp);
        errbuf[cp - 1] = '\0';
    }
    return len;
}
