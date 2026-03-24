#ifndef _TIME_H
#define _TIME_H

#include <stdint.h>
#include <stddef.h>

typedef int64_t time_t;
typedef int64_t suseconds_t;
typedef int clockid_t;

#define CLOCK_REALTIME  0
#define CLOCK_MONOTONIC 1

struct timespec {
    time_t tv_sec;
    long   tv_nsec;
};

struct timeval {
    time_t      tv_sec;
    suseconds_t tv_usec;
};

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

time_t time(time_t *t);
struct tm *gmtime_r(const time_t *timep, struct tm *result);
struct tm *localtime_r(const time_t *timep, struct tm *result);
size_t strftime(char *s, size_t max, const char *format, const struct tm *tm);
int gettimeofday(struct timeval *tv, struct timezone *tz);
time_t mktime(struct tm *tm);
int clock_gettime(clockid_t clk_id, struct timespec *tp);

#endif /* _TIME_H */
