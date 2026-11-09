/* Config reload (plan §6): re-read the shared document plus this node's local
 * overlay and apply a changed effective config live — heartbeat timer, cluster
 * transport, ctl socket, DHCP knobs, executor re-apply. An interface change
 * restarts the DHCP engine on the new interface (master-only, engine start is
 * the engine's own bootstrap, so the engine re-enters its state machine there).
 *
 * A file that no longer parses is refused and the current effective config is
 * kept: a bad edit never takes a live node down. Heartbeat, transport bind, ctl
 * socket, DHCP send knobs, members, priority, default_role and the election
 * timers all apply live; requested DHCP options and the hook script are read at
 * engine start, so a change to those alone takes effect on restart. */
#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/config.h"
#include "ha-dhcpc/ctl.h"
#include "ha-dhcpc/dhcpcore.h"
#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/log.h"
#include "ha-dhcpc/persist.h"
#include "ha-dhcpc/reload.h"
#include "internal.h"

static const struct in_addr *self_sync(hadc_ctx_t *ctx)
{
    for (size_t i = 0; i < ctx->conf.n_members; i++)
        if (!strcmp(ctx->conf.members[i].id, ctx->conf.self))
            return &ctx->conf.members[i].sync_address;
    return NULL;
}

static const struct in_addr *self_sync_of(hadc_conf_t *c)
{
    for (size_t i = 0; i < c->n_members; i++)
        if (!strcmp(c->members[i].id, c->self))
            return &c->members[i].sync_address;
    return NULL;
}

int hadc_conf_reload(hadc_ctx_t *ctx, const char *why)
{
    hadc_conf_t next;
    char err[512];
    char changes[512] = "";
    size_t n = 0;

    if (hadc_config_load(ctx->conf.base_path, ctx->conf.local_path, &next, err, sizeof(err)) != 0) {
        hadc_err("reload(%s): %s; keeping the config in use", why, err);
        return -1;
    }
    /* The file's designated_master is only the cold-start seed. Keep the
     * runtime master (possibly elected) unless the operator changed the seed,
     * so an unchanged reload compares equal and does nothing. */
    if (!strcmp(next.seed_master, ctx->conf.seed_master))
        memcpy(next.designated_master, ctx->conf.designated_master,
               sizeof(next.designated_master));
    if (memcmp(&next, &ctx->conf, sizeof(next)) == 0) {
        hadc_dbg("reload(%s): no change", why);
        return 0;
    }

    /* What changed, so the log says what was applied and what needs a restart. */
    int heartbeat = next.cluster.heartbeat_ms != ctx->conf.cluster.heartbeat_ms;
    const struct in_addr *sync_old = self_sync(ctx), *sync_new = self_sync_of(&next);
    int transport = next.cluster.port != ctx->conf.cluster.port ||
        (sync_old && sync_new && memcmp(sync_old, sync_new, sizeof(*sync_new)) != 0);
    int ctl = strcmp(next.ctl_socket, ctx->conf.ctl_socket) != 0;
    int interface_changed = strcmp(next.interface, ctx->conf.interface) != 0;
    int dhcp_knobs = next.dhcp.retention != ctx->conf.dhcp.retention ||
        next.dhcp.rate_limit_ms != ctx->conf.dhcp.rate_limit_ms ||
        next.dhcp.renew_retry_interval_s != ctx->conf.dhcp.renew_retry_interval_s ||
        next.dhcp.rediscover_in_retention != ctx->conf.dhcp.rediscover_in_retention ||
        strcmp(next.lease_file, ctx->conf.lease_file) != 0;
    int restart_only = next.dhcp.n_request_options != ctx->conf.dhcp.n_request_options ||
        strcmp(next.apply.dns_hook, ctx->conf.apply.dns_hook) != 0;
    /* read at use time from the merged conf, so swapping it is enough */
    int role_timers = next.default_role_master != ctx->conf.default_role_master ||
        next.priority != ctx->conf.priority ||
        next.cluster.election_deadline_ms != ctx->conf.cluster.election_deadline_ms ||
        next.cluster.cluster_timeout_ms != ctx->conf.cluster.cluster_timeout_ms ||
        next.cluster.quorum != ctx->conf.cluster.quorum ||
        strcmp(next.seed_master, ctx->conf.seed_master) != 0;
    int cluster_addrs = next.cluster.n_ifaces != ctx->conf.cluster.n_ifaces ||
        memcmp(next.cluster.ifaces, ctx->conf.cluster.ifaces,
               sizeof(next.cluster.ifaces)) != 0;
    int apply = interface_changed || cluster_addrs ||
        next.apply.routes != ctx->conf.apply.routes ||
        next.apply.backup_gateway.s_addr != ctx->conf.apply.backup_gateway.s_addr ||
        next.apply.slave_link_down != ctx->conf.apply.slave_link_down;

    if (heartbeat)
        n += (size_t)snprintf(changes + n, sizeof(changes) - n, "%sheartbeat", n ? " " : "");
    if (transport)
        n += (size_t)snprintf(changes + n, sizeof(changes) - n, "%stransport", n ? " " : "");
    if (ctl)
        n += (size_t)snprintf(changes + n, sizeof(changes) - n, "%sctl_socket", n ? " " : "");
    if (interface_changed)
        n += (size_t)snprintf(changes + n, sizeof(changes) - n, "%sinterface", n ? " " : "");
    if (dhcp_knobs)
        n += (size_t)snprintf(changes + n, sizeof(changes) - n, "%sdhcp", n ? " " : "");
    if (next.n_members != ctx->conf.n_members)
        n += (size_t)snprintf(changes + n, sizeof(changes) - n, "%smembers", n ? " " : "");
    if (role_timers)
        n += (size_t)snprintf(changes + n, sizeof(changes) - n, "%srole/priority/timers",
                              n ? " " : "");
    if (cluster_addrs)
        n += (size_t)snprintf(changes + n, sizeof(changes) - n, "%scluster_addresses",
                              n ? " " : "");
    if (restart_only)
        n += (size_t)snprintf(changes + n, sizeof(changes) - n, "%soptions/hook(needs restart)",
                              n ? " " : "");
    if (n == 0)
        snprintf(changes, sizeof(changes), "unspecified");

    if (strcmp(next.seed_master, ctx->conf.seed_master) != 0)
        hadc_info("reload: designated_master seed changed %s -> %s",
                  ctx->conf.seed_master[0] ? ctx->conf.seed_master : "(none)",
                  next.seed_master[0] ? next.seed_master : "(none)");

    ctx->conf = next;
    hadc_log_set_level(ctx->conf.loglevel);
    hadc_info("reload(%s): %s -> %s", why, ctx->conf.base_path, changes);

    if (heartbeat) {
        struct itimerspec its = {
            .it_interval = { .tv_sec = ctx->conf.cluster.heartbeat_ms / 1000,
                             .tv_nsec = (long)(ctx->conf.cluster.heartbeat_ms % 1000) * 1000000 },
            .it_value = { .tv_sec = ctx->conf.cluster.heartbeat_ms / 1000,
                          .tv_nsec = (long)(ctx->conf.cluster.heartbeat_ms % 1000) * 1000000 },
        };
        if (ctx->timerfd >= 0 && timerfd_settime(ctx->timerfd, 0, &its, NULL) != 0)
            hadc_warn("reload: timerfd re-arm failed: %s", strerror(errno));
    }
    if (transport)
        hadc_cluster_rebind(ctx);
    if (ctl)
        hadc_ctl_rebind(ctx);

    /* Executor first: the address and routes move to the new interface before
     * the engine starts speaking on it. */
    if (apply) {
        hadc_desired_t desired;
        hadc_executor_desired(ctx, &ctx->lease, &desired);
        hadc_executor_apply(ctx, &desired, "RELOAD");
        if (ctx->role == HADC_ROLE_MASTER && cluster_addrs)
            hadc_executor_announce_cluster(ctx);
    }
    if (dhcp_knobs)
        hadc_dhcpcore_reload(ctx);
    if (interface_changed)
        hadc_dhcpcore_restart(ctx);
    if (restart_only)
        hadc_warn("reload(%s): requested DHCP options and the hook script are read at engine "
                  "start; they take effect on restart",
                  why);

    hadc_persist_save(ctx);
    return 0;
}
