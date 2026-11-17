/* Executor state-commit tests: only fatal setup failures may stop executor
 * apply from recording the desired state as applied. Plus the drift self-heal
 * pre-init contract (no memo, no monitor, verification unknown). */

#include <arpa/inet.h>
#include <errno.h>
#include <jansson.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/executor.h"
#include "internal.h"

bool hadc_cluster_graceful_active(hadc_ctx_t *ctx)
{
    (void)ctx;
    return false;
}

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

    /* Server-id pin: the field is populated from the lease and participates in
     * the canonical hash, so a server-id change re-triggers apply and a stable
     * input yields a stable hash. */
    {
        struct in_addr gw, sid1, sid2;
        hadc_ctx_t ctx;
        hadc_lease_t lease;
        hadc_desired_t a, b;

        inet_pton(AF_INET, "143.177.172.1", &gw);
        inet_pton(AF_INET, "95.99.44.1", &sid1);
        inet_pton(AF_INET, "95.99.44.2", &sid2);

        memset(&ctx, 0, sizeof(ctx));
        memset(&lease, 0, sizeof(lease));
        ctx.role = HADC_ROLE_MASTER;
        lease.state = HADC_LEASE_BOUND;
        lease.address.s_addr = inet_addr("143.177.172.194");
        lease.netmask.s_addr = inet_addr("255.255.255.0");
        lease.gateway = gw;
        lease.server_id = sid1;

        hadc_executor_desired(&ctx, &lease, &a);
        if (a.server_id.s_addr != sid1.s_addr)
            return fail("server_id populated in desired state");

        lease.server_id = sid2;
        hadc_executor_desired(&ctx, &lease, &b);
        if (memcmp(a.config_hash, b.config_hash, sizeof(a.config_hash)) == 0)
            return fail("server_id change must change the canonical hash");

        lease.server_id = sid1;
        hadc_executor_desired(&ctx, &lease, &b);
        if (memcmp(a.config_hash, b.config_hash, sizeof(a.config_hash)) != 0)
            return fail("canonical hash must be stable for identical input");
    }

    /* Seamless takeover: while demoting with steering active, the desired state
     * steers via split /1s (steer_via = new master fabric nexthop) without
     * overriding the default route, keeps the VIPs assigned with ARP/source
     * suppression, and carries the NAT-bypass mark; all fields participate in
     * the canonical hash. */
    {
        struct in_addr gw, fabric, none;
        hadc_ctx_t ctx;
        hadc_lease_t lease;
        hadc_desired_t a, b;

        inet_pton(AF_INET, "143.177.172.1", &gw);
        inet_pton(AF_INET, "10.99.0.2", &fabric);
        none.s_addr = 0;

        memset(&ctx, 0, sizeof(ctx));
        memset(&lease, 0, sizeof(lease));
        ctx.role = HADC_ROLE_DEMOTING;
        ctx.handoff_forward_hold = true;
        ctx.demote_route_via_new_master_active = true;
        ctx.conf.apply.slave_sync_wan = true;
        ctx.conf.apply.demote_nat_bypass_mark = 0x2e05;
        snprintf(ctx.conf.designated_master, sizeof(ctx.conf.designated_master), "%s", "node-b");
        ctx.conf.n_members = 1;
        snprintf(ctx.conf.members[0].id, sizeof(ctx.conf.members[0].id), "%s", "node-b");
        ctx.conf.members[0].sync_address = fabric;
        ctx.conf.cluster.n_ifaces = 1;
        snprintf(ctx.conf.cluster.ifaces[0].interface,
                 sizeof(ctx.conf.cluster.ifaces[0].interface), "%s", "br-lan");
        ctx.conf.cluster.ifaces[0].n_addrs = 1;
        inet_pton(AF_INET, "192.168.10.1", &ctx.conf.cluster.ifaces[0].addrs[0].address);
        ctx.conf.cluster.ifaces[0].addrs[0].prefixlen = 24;

        lease.state = HADC_LEASE_BOUND;
        lease.address.s_addr = inet_addr("143.177.172.194");
        lease.netmask.s_addr = inet_addr("255.255.255.0");
        lease.gateway = gw;

        hadc_executor_desired(&ctx, &lease, &a);
        if (a.steer_via.s_addr != fabric.s_addr)
            return fail("steering nexthop is the new master fabric address");
        if (a.default_via.s_addr != none.s_addr)
            return fail("steering must not override the default route");
        if (a.gateway.s_addr != gw.s_addr)
            return fail("steering keeps the lease gateway");
        if (!a.cluster_addrs_present || !a.vip_hold_suppress)
            return fail("steering holds the VIPs with ARP/source suppression");
        if (a.nat_bypass_mark != 0x2e05)
            return fail("NAT-bypass mark carried while steering");
        if (a.nat_bypass_notrack)
            return fail("notrack off in config means off in desired state");
        ctx.conf.apply.demote_notrack = true;
        hadc_executor_desired(&ctx, &lease, &b);
        if (!b.nat_bypass_notrack)
            return fail("notrack carried into desired state while steering");
        if (memcmp(a.config_hash, b.config_hash, sizeof(a.config_hash)) == 0)
            return fail("notrack must change the canonical hash");
        ctx.conf.apply.demote_notrack = false;
        hadc_executor_desired(&ctx, &lease, &b);
        if (memcmp(a.config_hash, b.config_hash, sizeof(a.config_hash)) != 0)
            return fail("canonical hash must be stable for identical input");
        ctx.conf.apply.demote_notrack = true;
        hadc_executor_desired(&ctx, &lease, &a);

        ctx.demote_route_via_new_master_active = false;
        hadc_executor_desired(&ctx, &lease, &b);
        if (b.steer_via.s_addr != none.s_addr || b.vip_hold_suppress || b.nat_bypass_mark)
            return fail("feature off: no steering, no VIP hold, no mark");
        if (b.cluster_addrs_present)
            return fail("feature off: demoting drops the VIPs");
        if (memcmp(a.config_hash, b.config_hash, sizeof(a.config_hash)) == 0)
            return fail("steering state must change the canonical hash");
        ctx.demote_route_via_new_master_active = true;
        hadc_executor_desired(&ctx, &lease, &b);
        if (memcmp(a.config_hash, b.config_hash, sizeof(a.config_hash)) != 0)
            return fail("canonical hash must be stable for identical input");
    }

    /* VIP splits for seamless-takeover steering: the two sub-prefixes at
     * prefixlen+1 covering each cluster address's subnet; host prefixes and
     * subnets containing the steering nexthop are skipped; duplicates collapse. */
    {
        hadc_desired_t d;
        struct in_addr via;
        vip_split_t out[VIP_SPLIT_MAX];
        size_t n;

        memset(&d, 0, sizeof(d));
        inet_pton(AF_INET, "10.0.0.2", &via);

        d.n_cluster_ifaces = 1;
        d.cluster_ifaces[0].n_addrs = 1;
        inet_pton(AF_INET, "192.168.101.1", &d.cluster_ifaces[0].addrs[0].address);
        d.cluster_ifaces[0].addrs[0].prefixlen = 24;
        n = vip_splits(&d, &via, out, VIP_SPLIT_MAX);
        if (n != 2)
            return fail("VIP /24 yields two /25 splits");
        if (out[0].net.s_addr != inet_addr("192.168.101.0") || out[0].plen != 25)
            return fail("lower VIP split wrong");
        if (out[1].net.s_addr != inet_addr("192.168.101.128") || out[1].plen != 25)
            return fail("upper VIP split wrong");

        d.cluster_ifaces[0].n_addrs = 2;
        inet_pton(AF_INET, "192.168.101.2", &d.cluster_ifaces[0].addrs[1].address);
        d.cluster_ifaces[0].addrs[1].prefixlen = 24;
        n = vip_splits(&d, &via, out, VIP_SPLIT_MAX);
        if (n != 2)
            return fail("same-subnet VIPs must dedup");

        inet_pton(AF_INET, "192.168.101.9", &via);
        n = vip_splits(&d, &via, out, VIP_SPLIT_MAX);
        if (n != 0)
            return fail("nexthop inside the VIP subnet must skip the splits");
        inet_pton(AF_INET, "10.0.0.2", &via);

        d.cluster_ifaces[0].n_addrs = 1;
        inet_pton(AF_INET, "10.50.0.1", &d.cluster_ifaces[0].addrs[0].address);
        d.cluster_ifaces[0].addrs[0].prefixlen = 24;
        n = vip_splits(&d, &via, out, VIP_SPLIT_MAX);
        if (n != 2 || out[0].net.s_addr != inet_addr("10.50.0.0") ||
            out[1].net.s_addr != inet_addr("10.50.0.128") || out[0].plen != 25 || out[1].plen != 25)
            return fail("second VIP subnet splits wrong");

        d.cluster_ifaces[0].addrs[0].prefixlen = 32;
        n = vip_splits(&d, &via, out, VIP_SPLIT_MAX);
        if (n != 0)
            return fail("host-prefix VIPs have no split to add");
    }

    printf("executor_test: OK\n");
    return 0;
}
