/* HA-DHCPC logging + event loop primitives (M0, frozen). */
#ifndef HA_DHCPC_LOG_H
#define HA_DHCPC_LOG_H

#include <stdarg.h>
#include <stdbool.h>

typedef enum { HADC_LOG_DEBUG, HADC_LOG_INFO, HADC_LOG_WARN, HADC_LOG_ERR } hadc_log_level_t;

void hadc_log(hadc_log_level_t level, const char *fmt, ...);
/* Minimum level emitted (default INFO; set from the config's loglevel). */
void hadc_log_set_level(hadc_log_level_t level);
#define hadc_dbg(...)  hadc_log(HADC_LOG_DEBUG, __VA_ARGS__)
#define hadc_info(...) hadc_log(HADC_LOG_INFO, __VA_ARGS__)
#define hadc_warn(...) hadc_log(HADC_LOG_WARN, __VA_ARGS__)
#define hadc_err(...)  hadc_log(HADC_LOG_ERR, __VA_ARGS__)

/* Monotonic clock in milliseconds (timers are monotonic; plan §8). */
long long hadc_now_ms(void);

#endif /* HA_DHCPC_LOG_H */
