/* Time utilities for Telix — UTC only. */
#include <time.h>
#include <telix/syscall.h>
#include <string.h>

/* clock_gettime from kernel (returns nanoseconds since boot). */
extern uint64_t __telix_clock_gettime(void);

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    (void)clk_id;
    uint64_t ns = __telix_clock_gettime();
    tp->tv_sec = (time_t)(ns / 1000000000ULL);
    tp->tv_nsec = (long)(ns % 1000000000ULL);
    return 0;
}

time_t time(time_t *t) {
    uint64_t ns = __telix_clock_gettime();
    time_t sec = (time_t)(ns / 1000000000ULL);
    if (t) *t = sec;
    return sec;
}

int gettimeofday(struct timeval *tv, struct timezone *tz) {
    uint64_t ns = __telix_clock_gettime();
    if (tv) {
        tv->tv_sec = (time_t)(ns / 1000000000ULL);
        tv->tv_usec = (suseconds_t)((ns % 1000000000ULL) / 1000);
    }
    if (tz) {
        tz->tz_minuteswest = 0;
        tz->tz_dsttime = 0;
    }
    return 0;
}

static const int days_in_month[] = {31,28,31,30,31,30,31,31,30,31,30,31};

static int is_leap(int year) {
    return (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0));
}

struct tm *gmtime_r(const time_t *timep, struct tm *result) {
    time_t t = *timep;
    int days = (int)(t / 86400);
    int rem = (int)(t % 86400);
    if (rem < 0) { rem += 86400; days--; }

    result->tm_hour = rem / 3600;
    rem %= 3600;
    result->tm_min = rem / 60;
    result->tm_sec = rem % 60;

    /* Day of week: Jan 1 1970 was Thursday (4). */
    result->tm_wday = (days + 4) % 7;
    if (result->tm_wday < 0) result->tm_wday += 7;

    int year = 1970;
    while (days >= (is_leap(year) ? 366 : 365)) {
        days -= is_leap(year) ? 366 : 365;
        year++;
    }
    while (days < 0) {
        year--;
        days += is_leap(year) ? 366 : 365;
    }

    result->tm_year = year - 1900;
    result->tm_yday = days;
    result->tm_isdst = 0;

    int mon = 0;
    for (mon = 0; mon < 12; mon++) {
        int dim = days_in_month[mon];
        if (mon == 1 && is_leap(year)) dim++;
        if (days < dim) break;
        days -= dim;
    }
    result->tm_mon = mon;
    result->tm_mday = days + 1;

    return result;
}

struct tm *localtime_r(const time_t *timep, struct tm *result) {
    return gmtime_r(timep, result);
}

time_t mktime(struct tm *tm) {
    int year = tm->tm_year + 1900;
    int mon = tm->tm_mon;
    time_t days = 0;

    for (int y = 1970; y < year; y++)
        days += is_leap(y) ? 366 : 365;

    for (int m = 0; m < mon; m++) {
        days += days_in_month[m];
        if (m == 1 && is_leap(year)) days++;
    }
    days += tm->tm_mday - 1;

    return days * 86400 + tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec;
}

static void append_num(char **p, char *end, int val, int width) {
    char buf[16];
    int i = 0;
    int v = val < 0 ? -val : val;
    do { buf[i++] = '0' + (v % 10); v /= 10; } while (v > 0);
    while (i < width) buf[i++] = '0';
    for (int j = i - 1; j >= 0 && *p < end; j--)
        *(*p)++ = buf[j];
}

size_t strftime(char *s, size_t max, const char *format, const struct tm *tm) {
    char *p = s;
    char *end = s + max - 1;

    while (*format && p < end) {
        if (*format != '%') {
            *p++ = *format++;
            continue;
        }
        format++;
        switch (*format) {
        case 'Y': append_num(&p, end, tm->tm_year + 1900, 4); break;
        case 'm': append_num(&p, end, tm->tm_mon + 1, 2); break;
        case 'd': append_num(&p, end, tm->tm_mday, 2); break;
        case 'H': append_num(&p, end, tm->tm_hour, 2); break;
        case 'M': append_num(&p, end, tm->tm_min, 2); break;
        case 'S': append_num(&p, end, tm->tm_sec, 2); break;
        case 'Z':
            if (p + 3 <= end) { *p++ = 'U'; *p++ = 'T'; *p++ = 'C'; }
            break;
        case '%':
            *p++ = '%';
            break;
        case '\0':
            goto done;
        default:
            if (p + 1 < end) { *p++ = '%'; *p++ = *format; }
            break;
        }
        format++;
    }
done:
    *p = '\0';
    return (size_t)(p - s);
}
