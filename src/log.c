#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "ha-dhcpc/log.h"

static const char *LEVELS[] = { "debug", "info", "warn", "err" };

void hadc_log(hadc_log_level_t level, const char *fmt, ...)
{
    va_list ap;
    struct timespec ts;
    char tsbuf[32];

    clock_gettime(CLOCK_REALTIME, &ts);
    snprintf(tsbuf, sizeof(tsbuf), "%lld.%03lld", (long long)ts.tv_sec,
             (long long)(ts.tv_nsec / 1000000));

    fprintf(stderr, "ha-dhcpc[%d] %s ", (int)getpid(), LEVELS[level]);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
    (void)tsbuf;
}

long long hadc_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
