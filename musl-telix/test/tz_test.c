/* Test: locale and timezone (Phase 72).
 * Calls time/gmtime_r/strftime, verifies basic sanity.
 */
#include <time.h>
#include <locale.h>
#include <string.h>

extern long write(int fd, const void *buf, unsigned long count);
extern void _exit(int status) __attribute__((noreturn));

static void puts_s(const char *s) {
    int n = 0;
    while (s[n]) n++;
    write(1, s, n);
}

int main(int argc, char **argv, char **envp) {
    (void)argc; (void)argv; (void)envp;

    /* Test setlocale. */
    char *loc = setlocale(LC_ALL, "C");
    if (!loc || loc[0] != 'C') {
        puts_s("tz_test: setlocale FAIL\n");
        _exit(1);
    }

    /* Test localeconv. */
    struct lconv *lc = localeconv();
    if (!lc || lc->decimal_point[0] != '.') {
        puts_s("tz_test: localeconv FAIL\n");
        _exit(1);
    }

    /* Test time/gmtime_r. */
    time_t t = time(0);
    /* t should be > 0 since clock has been running. */
    struct tm tm;
    gmtime_r(&t, &tm);

    /* Year should be >= 1970 (could be 1970 if clock just started). */
    if (tm.tm_year + 1900 < 1970) {
        puts_s("tz_test: gmtime_r year FAIL\n");
        _exit(1);
    }

    /* Test strftime. */
    char buf[64];
    size_t len = strftime(buf, sizeof(buf), "%Y-%m-%d %Z", &tm);
    if (len == 0) {
        puts_s("tz_test: strftime FAIL\n");
        _exit(1);
    }

    /* Verify UTC appears in output. */
    int found_utc = 0;
    for (size_t i = 0; i + 2 < len; i++) {
        if (buf[i] == 'U' && buf[i+1] == 'T' && buf[i+2] == 'C') {
            found_utc = 1;
            break;
        }
    }
    if (!found_utc) {
        puts_s("tz_test: strftime no UTC FAIL\n");
        _exit(1);
    }

    /* Test mktime roundtrip. */
    time_t t2 = mktime(&tm);
    /* Should be close to t (within 1 second). */
    long diff = (long)(t2 - t);
    if (diff < -1 || diff > 1) {
        puts_s("tz_test: mktime roundtrip FAIL\n");
        _exit(1);
    }

    puts_s("tz_test: PASSED\n");
    _exit(0);
}
