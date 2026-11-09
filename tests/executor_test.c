/* Executor state-commit tests: only fatal setup failures may stop executor
 * apply from recording the desired state as applied. Plus the drift self-heal
 * pre-init contract (no memo, no monitor, verification unknown). */
#define _GNU_SOURCE

#include <arpa/inet.h>
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

/* The gateway probe lives in ping.c; executor.c only links against this. */
static bool g_gwping_unreachable;

bool hadc_gwping_unreachable(void)
{
    return g_gwping_unreachable;
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

    /* Master default-route failover: while the probe verdict is a timeout or
     * there is no lease IP yet, the default goes to the configured backup
     * router; it hands back to the lease gateway when both are healthy. */
    {
        struct in_addr backup, gw, none;
        hadc_ctx_t ctx;
        hadc_lease_t lease;
        hadc_desired_t d;

        inet_pton(AF_INET, "192.168.10.3", &backup);
        inet_pton(AF_INET, "143.177.172.1", &gw);
        none.s_addr = 0;

        memset(&ctx, 0, sizeof(ctx));
        memset(&lease, 0, sizeof(lease));
        ctx.role = HADC_ROLE_MASTER;
        ctx.conf.apply.master_backup_gateway = backup;
        lease.state = HADC_LEASE_BOUND;
        inet_pton(AF_INET, "143.177.172.194", &lease.address);
        lease.gateway = gw;

        g_gwping_unreachable = false;
        hadc_executor_desired(&ctx, &lease, &d);
        if (d.gateway.s_addr != gw.s_addr || d.default_via.s_addr != none.s_addr)
            return fail("healthy gateway keeps the lease default");

        g_gwping_unreachable = true;
        hadc_executor_desired(&ctx, &lease, &d);
        if (d.gateway.s_addr != gw.s_addr || d.default_via.s_addr != backup.s_addr)
            return fail("unanswered probe moves the default to the backup router");

        g_gwping_unreachable = false;
        lease.address = none; /* no IP yet */
        hadc_executor_desired(&ctx, &lease, &d);
        if (d.default_via.s_addr != backup.s_addr)
            return fail("no lease IP yet uses the backup router");
        lease.address.s_addr = inet_addr("143.177.172.194");

        /* Slaves are unaffected: their default is the backup_gateway route. */
        ctx.role = HADC_ROLE_SLAVE;
        g_gwping_unreachable = true;
        hadc_executor_desired(&ctx, &lease, &d);
        if (d.default_via.s_addr != none.s_addr)
            return fail("slave keeps its own default route");
    }

    printf("executor_test: OK\n");
    return 0;
}
