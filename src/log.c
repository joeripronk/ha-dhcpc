#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "ha-dhcpc/log.h"

static const char *LEVELS[] = { "debug", "info", "warn", "err" };
static const int SYSLOG_LEVELS[] = { LOG_DEBUG, LOG_INFO, LOG_WARNING, LOG_ERR };

static hadc_log_level_t g_min_level = HADC_LOG_INFO;
static bool g_syslog_open;

void hadc_log_set_level(hadc_log_level_t level)
{
    g_min_level = level;
}

void hadc_log(hadc_log_level_t level, const char *fmt, ...)
{
    va_list ap, ap2;

    if (level < g_min_level)
        return;

    if (!g_syslog_open) {
        openlog("ha-dhcpc", LOG_PID | LOG_NDELAY, LOG_DAEMON);
        g_syslog_open = true;
    }

    va_start(ap, fmt);
    va_copy(ap2, ap);
    fprintf(stderr, "ha-dhcpc[%d] %s ", (int)getpid(), LEVELS[level]);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    fflush(stderr);
    vsyslog(SYSLOG_LEVELS[level], fmt, ap2);
    va_end(ap2);
    va_end(ap);
}

long long hadc_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
