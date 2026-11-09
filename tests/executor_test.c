/* Executor state-commit tests: only fatal setup failures may stop executor
 * apply from recording the desired state as applied. Plus the drift self-heal
 * pre-init contract (no memo, no monitor, verification unknown). */
#define _GNU_SOURCE

#include <errno.h>
#include <jansson.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "ha-dhcpc/executor.h"
#include "internal.h"

/* The event loop lives in main.c; executor.c only links against these. */
int hadc_loop_add(hadc_ctx_t *ctx, int fd, hadc_fd_cb_t cb, int events)
{
    (void)ctx; (void)fd; (void)cb; (void)events;
    return 0;
}

int hadc_loop_del(hadc_ctx_t *ctx, int fd)
{
    (void)ctx; (void)fd;
    return 0;
}

static int fail(const char *what)
{
    printf("executor_test: FAIL (%s)\n", what);
    return 1;
}

int main(void)
{
    if (executor_action_is_fatal(-ENOENT, false))
        return fail("nonfatal action failure");
    if (executor_action_is_fatal(0, true))
        return fail("successful action");
    if (!executor_action_is_fatal(-ENOENT, true))
        return fail("fatal action failure");

    /* Drift self-heal before init: nothing is applied, verification is
     * unknown, no reconciliation has run, the monitor is down, and the
     * monitor cannot start without the command socket. */
    {
        hadc_ctx_t ctx;
        json_t *st;
        json_t *v;

        memset(&ctx, 0, sizeof(ctx));
        if (hadc_executor_monitor_start(&ctx) != -1)
            return fail("monitor start without netlink socket");
        st = hadc_executor_status();
        if (!st)
            return fail("status json");
        v = json_object_get(st, "verified");
        if (!json_is_integer(v) || json_integer_value(v) != -1) {
            json_decref(st);
            return fail("pre-init verified state");
        }
        v = json_object_get(st, "drift_reconciled");
        if (!json_is_integer(v) || json_integer_value(v) != 0) {
            json_decref(st);
            return fail("pre-init drift count");
        }
        v = json_object_get(st, "monitor");
        if (!json_is_false(v)) {
            json_decref(st);
            return fail("pre-init monitor state");
        }
        json_decref(st);
    }

    printf("executor_test: OK\n");
    return 0;
}
