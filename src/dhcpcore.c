/* DHCP engine adapter (plan §3). Master-only by contract: drives the
 * vendored FreeBSD dhclient core (src/dhcp/) from the daemon event loop.
 * The core exposes its protocol fds (dhcp_core_get_fds) and its earliest
 * timeout (dhcp_core_next_timeout_ms); the daemon registers them with its
 * epoll loop and pumps dispatch_step()/dhcp_core_run_timeouts() when they
 * fire. Reasons come back through dhcp_core_set_hooks and are mapped onto
 * the frozen daemon callbacks. */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/timerfd.h>

#include "ha-dhcpc/dhcpcore.h"
#include "ha-dhcpc/lease.h"
#include "ha-dhcpc/log.h"
#include "internal.h"

#include "dhcpd.h"

#define CORE_FDS_MAX 32

static const hadc_dhcp_callbacks_t *g_cb;
static void *g_cbarg;
static uint64_t g_lease_version;

static void core_arm_timer(hadc_ctx_t *ctx)
{
    long ms = dhcp_core_next_timeout_ms();
    struct itimerspec its = { 0 };

    if (ms <= 0)
        ms = 1; /* already expired: fire on the next loop tick */
    its.it_value.tv_sec = ms / 1000;
    its.it_value.tv_nsec = (long)(ms % 1000) * 1000000L;
    timerfd_settime(ctx->core_timerfd, 0, &its, NULL);
}

static void core_fd_ready(hadc_ctx_t *ctx, int fd)
{
    (void)ctx;
    (void)fd;
    dispatch_step();
}

static void core_timer_ready(hadc_ctx_t *ctx, int fd)
{
    uint64_t exp;

    if (read(fd, &exp, sizeof(exp)) == -1)
        return;
    dhcp_core_run_timeouts();
    core_arm_timer(ctx);
}

static void fill_lease(hadc_lease_t *out, const struct client_lease *l)
{
    const struct option_data *dns;
    struct timespec mono;
    long long now_utc = (long long)time(NULL);

    clock_gettime(CLOCK_MONOTONIC, &mono);

    memset(out, 0, sizeof(*out));
    out->state = HADC_LEASE_BOUND;
    if (l->address.len == 4)
        memcpy(&out->address, l->address.iabuf, 4);
    if (l->options[DHO_SUBNET_MASK].data != NULL &&
        l->options[DHO_SUBNET_MASK].len == 4)
        memcpy(&out->netmask, l->options[DHO_SUBNET_MASK].data, 4);
    if (l->options[DHO_ROUTERS].data != NULL &&
        l->options[DHO_ROUTERS].len >= 4)
        memcpy(&out->gateway, l->options[DHO_ROUTERS].data, 4);
    if (l->options[DHO_DHCP_SERVER_IDENTIFIER].data != NULL &&
        l->options[DHO_DHCP_SERVER_IDENTIFIER].len == 4)
        memcpy(&out->server_id, l->options[DHO_DHCP_SERVER_IDENTIFIER].data, 4);
    dns = &l->options[DHO_DOMAIN_NAME_SERVERS];
    for (size_t off = 0; dns->data != NULL && off + 4 <= dns->len &&
         out->n_dns < HADC_DNS_MAX; off += 4)
        memcpy(&out->dns[out->n_dns++], dns->data + off, 4);

    /* Core deadlines are monotonic (cur_time). Convert to absolute UTC anchors
     * so every node/restart derives identical remaining time from the clock. */
    out->obtained_at_utc = now_utc;
    if (l->renewal > 0)
        out->t1_at_utc = now_utc + (long long)(l->renewal - mono.tv_sec);
    if (l->rebind > 0)
        out->t2_at_utc = now_utc + (long long)(l->rebind - mono.tv_sec);
    if (l->expiry > 0)
        out->t3_at_utc = now_utc + (long long)(l->expiry - mono.tv_sec);
}

static int is_lease_reason(const char *reason)
{
    return strcmp(reason, "BOUND") == 0 || strcmp(reason, "RENEW") == 0 ||
           strcmp(reason, "REBOOT") == 0 || strcmp(reason, "REBIND") == 0 ||
           strcmp(reason, "BOOT") == 0;
}

static void adapter_on_reason(void *arg, const char *reason,
                              struct client_lease *new_lease)
{
    hadc_ctx_t *ctx = arg;

    if (g_cb == NULL)
        return;

    if (strcmp(reason, "RETAINED-ENTER") == 0) {
        if (g_cb->on_retention != NULL)
            g_cb->on_retention(g_cbarg, true);
        return;
    }
    if (strcmp(reason, "RETAINED-EXIT") == 0) {
        if (g_cb->on_retention != NULL)
            g_cb->on_retention(g_cbarg, false);
        return;
    }
    if (strcmp(reason, "CARRIER-RETURN") == 0) {
        if (g_cb->on_carrier_return != NULL)
            g_cb->on_carrier_return(g_cbarg);
        return;
    }
    if (is_lease_reason(reason)) {
        if (g_cb->on_lease_update != NULL && new_lease != NULL) {
            hadc_lease_t l;

            fill_lease(&l, new_lease);
            if (strcmp(reason, "RENEW") == 0)
                l.state = HADC_LEASE_RENEW;
            else if (strcmp(reason, "REBIND") == 0)
                l.state = HADC_LEASE_REBIND;
            else
                l.state = HADC_LEASE_BOUND;
            /* Versions must never regress across role changes (plan §4). */
            if (g_lease_version < ctx->lease.version)
                g_lease_version = ctx->lease.version;
            l.version = ++g_lease_version;
            g_cb->on_lease_update(g_cbarg, &l);
        }
        return;
    }
    if ((strcmp(reason, "EXPIRE") == 0 || strcmp(reason, "FAIL") == 0) &&
        g_cb->on_lease_update != NULL) {
        g_cb->on_lease_update(g_cbarg, NULL);
        return;
    }
    hadc_dbg("dhcpcore: reason %s (no daemon action)", reason);
}

int hadc_dhcpcore_init(hadc_ctx_t *ctx, const hadc_dhcp_callbacks_t *cb, void *arg)
{
    g_cb = cb;
    g_cbarg = arg;
    hadc_info("dhcpcore: adapter ready (master-only engine)");
    (void)ctx;
    return 0;
}

static int g_core_live;    /* core inited once; never re-inited */
static int g_running;       /* fds + timerfd registered with the loop */
static int g_core_fds[CORE_FDS_MAX];
static int g_n_core_fds;
static char g_lease_db[PATH_MAX]; /* lease DB we last told the core about */
static hadc_ctx_t *g_ctx;         /* for the core's fd-closed notification */

/* The core closed one of its protocol fds (dead packet socket, removed
 * interface). Drop it from our bookkeeping and from the daemon's epoll set
 * immediately, while the number is still closed: otherwise a later stop or
 * restart would deregister whatever unrelated fd has since reused the
 * number. */
void dhcp_core_fd_closed(int fd)
{
    for (int i = 0; i < g_n_core_fds; i++)
        if (g_core_fds[i] == fd) {
            g_core_fds[i] = g_core_fds[--g_n_core_fds];
            break;
        }
    if (g_ctx != NULL)
        hadc_loop_del(g_ctx, fd);
}

int hadc_dhcpcore_start(hadc_ctx_t *ctx)
{
    char conf[HADC_PATH_MAX + 32];
    int fds[CORE_FDS_MAX];
    int nfds;

    if (!(ctx->role == HADC_ROLE_MASTER || ctx->role == HADC_ROLE_PROMOTING)) {
        hadc_dbg("dhcpcore: not started (slaves are passive to DHCP)");
        return 0;
    }
    if (g_running)
        return 0;

    g_ctx = ctx;

    if (!g_core_live) {
        /* Options the daemon's lease summary needs must be declared in the
         * core's config or ISC storage rules drop them from the lease. */
        size_t n = snprintf(conf, sizeof(conf),
                            "request subnet-mask, routers, domain-name-servers, "
                            "dhcp-server-identifier;\n");
        snprintf(conf + n, sizeof(conf) - n, "script \"%s\";\n",
                 ctx->conf.apply.dns_hook[0] != '\0' ? ctx->conf.apply.dns_hook
                                                    : "");
        dhcp_core_set_conf_text(conf);
        dhcp_core_set_hooks(adapter_on_reason, ctx);
        dhcp_core_set_retention(ctx->conf.dhcp.retention != HADC_RETENTION_OFF,
                                 ctx->conf.dhcp.rediscover_in_retention ? 1 : 0, 0, 0);
        dhcp_core_set_rate_limit_ms(ctx->conf.dhcp.rate_limit_ms);
        dhcp_core_set_renew_retry_interval_s(ctx->conf.dhcp.renew_retry_interval_s);

        /* No lease DB on this node: hand the engine the daemon's persisted (or
         * synced) lease, so a restart reuses the state and the next action is
         * the renewal that is actually due (plan §3/§5/§8). */
        if (!ctx->conf.lease_file[0] && ctx->lease.address.s_addr != 0) {
            struct dhcp_core_lease p;
            uint32_t t1, t2, t3;
            hadc_lease_remaining(&ctx->lease, (long long)time(NULL), &t1, &t2, &t3);
            memset(&p, 0, sizeof(p));
            memcpy(p.address, &ctx->lease.address, 4);
            memcpy(p.netmask, &ctx->lease.netmask, 4);
            memcpy(p.gateway, &ctx->lease.gateway, 4);
            memcpy(p.server_id, &ctx->lease.server_id, 4);
            for (size_t i = 0; i < ctx->lease.n_dns && p.n_dns < 8; i++)
                memcpy(p.dns[p.n_dns++], &ctx->lease.dns[i], 4);
            p.t1_remaining_s = (time_t)t1;
            p.t2_remaining_s = (time_t)t2;
            p.t3_remaining_s = (time_t)t3;
            dhcp_core_preset_lease(&p);
        }

        if (dhcp_core_start(ctx->conf.interface, ctx->conf.lease_file, NULL) != 0) {
            hadc_err("dhcpcore: core start failed");
            return -1;
        }
        snprintf(g_lease_db, sizeof(g_lease_db), "%s", ctx->conf.lease_file);
        for (size_t i = 0; i < ctx->conf.dhcp.n_request_options; i++)
            dhcp_core_add_requested_option(ctx->conf.dhcp.request_options[i]);
        ctx->core_timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (ctx->core_timerfd < 0) {
            hadc_err("dhcpcore: timerfd failed");
            return -1;
        }
        g_core_live = 1;
    } else if (!g_running) {
        /* Re-promotion after a demotion: the core kept its lease but its
         * timeouts froze while it was not being pumped. Cancel them, advance
         * the clock to now, and re-enter on the held lease with the daemon's
         * aged timers so the next action is the renewal that is due now, not a
         * stale-reboot DISCOVER. */
        {
            uint32_t t1, t2, t3;
            hadc_lease_remaining(&ctx->lease, (long long)time(NULL), &t1, &t2, &t3);
            if (dhcp_core_resume(ctx->conf.interface, (long)t1, (long)t2, (long)t3) != 0)
                hadc_warn("dhcpcore: resume on %s failed; re-registering as-is",
                          ctx->conf.interface);
        }
    }

    if (hadc_loop_add(ctx, ctx->core_timerfd, core_timer_ready, 0) != 0) {
        hadc_err("dhcpcore: core timer setup failed");
        return -1;
    }
    nfds = dhcp_core_get_fds(fds, CORE_FDS_MAX);
    for (int i = 0; i < nfds; i++) {
        if (hadc_loop_add(ctx, fds[i], core_fd_ready, HADC_FD_ERR_DROP) != 0) {
            hadc_err("dhcpcore: epoll register fd %d failed", fds[i]);
            return -1;
        }
        if (g_n_core_fds < CORE_FDS_MAX)
            g_core_fds[g_n_core_fds++] = fds[i];
    }
    core_arm_timer(ctx);
    g_running = 1;

    hadc_info("dhcpcore: engine running on %s (%d fds, retention=%s)",
              ctx->conf.interface, nfds,
              ctx->conf.dhcp.retention == HADC_RETENTION_OFF ? "off" : "on");
    return 0;
}

int hadc_dhcpcore_stop(hadc_ctx_t *ctx)
{
    if (!g_running)
        return 0;
    for (int i = 0; i < g_n_core_fds; i++)
        hadc_loop_del(ctx, g_core_fds[i]);
    g_n_core_fds = 0;
    hadc_loop_del(ctx, ctx->core_timerfd);
    g_running = 0;
    hadc_info("dhcpcore: engine stopped (slaves are passive to DHCP)");
    return 0;
}

/* Config reload (plan §6): push the live-settable knobs to a running engine.
 * The requested-options list and the hook script are read at engine start, so
 * a change there needs the restart below. The lease DB path is re-pointed (the
 * file itself is not moved by us). */
int hadc_dhcpcore_reload(hadc_ctx_t *ctx)
{
    if (!g_running)
        return 0;
    dhcp_core_set_retention(ctx->conf.dhcp.retention != HADC_RETENTION_OFF,
                             ctx->conf.dhcp.rediscover_in_retention ? 1 : 0, 0, 0);
    dhcp_core_set_rate_limit_ms(ctx->conf.dhcp.rate_limit_ms);
    dhcp_core_set_renew_retry_interval_s(ctx->conf.dhcp.renew_retry_interval_s);
    if (strcmp(ctx->conf.lease_file, g_lease_db) != 0) {
        dhcp_core_set_lease_db(ctx->conf.lease_file);
        snprintf(g_lease_db, sizeof(g_lease_db), "%s", ctx->conf.lease_file);
        hadc_info("dhcpcore: lease DB is now %s (the file itself is not moved)", g_lease_db);
    }
    return 0;
}

/* The interface changed: drop our epoll registrations for the core's fds before
 * the core closes them, re-enter the engine on the new interface, then register
 * its current fds again. The core refuses (and touches nothing) when the new
 * interface is absent or has no carrier; our registrations are restored then. */
int hadc_dhcpcore_restart(hadc_ctx_t *ctx)
{
    int fds[CORE_FDS_MAX];

    if (!g_running)
        return 0; /* nothing registered: the next start uses the new interface */

    for (int i = 0; i < g_n_core_fds; i++)
        hadc_loop_del(ctx, g_core_fds[i]);
    g_n_core_fds = 0;

    int refused = dhcp_core_restart(ctx->conf.interface, ctx->conf.lease_file) != 0;
    if (!refused)
        snprintf(g_lease_db, sizeof(g_lease_db), "%s", ctx->conf.lease_file);

    int n = dhcp_core_get_fds(fds, CORE_FDS_MAX);
    for (int i = 0; i < n; i++)
        if (hadc_loop_add(ctx, fds[i], core_fd_ready, HADC_FD_ERR_DROP) == 0 && g_n_core_fds < CORE_FDS_MAX)
            g_core_fds[g_n_core_fds++] = fds[i];
    core_arm_timer(ctx);

    if (refused) {
        hadc_warn("dhcpcore: restart on %s refused; staying on the current setup",
                  ctx->conf.interface);
        return -1;
    }
    hadc_info("dhcpcore: re-entered on %s (%d fds)", ctx->conf.interface, n);
    return 0;
}

int hadc_dhcpcore_force_discover(hadc_ctx_t *ctx)
{
    if (!g_running) {
        if (hadc_dhcpcore_start(ctx) != 0 || !g_running)
            return -1;
    }
    if (dhcp_core_force_discover(ctx->conf.interface) != 0) {
        hadc_warn("dhcpcore: forced discover on %s failed", ctx->conf.interface);
        return -1;
    }
    core_arm_timer(ctx);
    return 0;
}

int hadc_dhcpcore_force_renew(hadc_ctx_t *ctx)
{
    if (!g_running) {
        if (hadc_dhcpcore_start(ctx) != 0 || !g_running)
            return -1;
    }
    if (dhcp_core_force_renew(ctx->conf.interface) != 0) {
        hadc_warn("dhcpcore: forced renew on %s failed", ctx->conf.interface);
        return -1;
    }
    core_arm_timer(ctx);
    return 0;
}

int hadc_dhcpcore_write_lease_file(hadc_ctx_t *ctx, const hadc_lease_t *lease)
{
    char path[PATH_MAX], tmp[PATH_MAX + 8], buf[64], buf2[64];
    time_t now = time(NULL);
    FILE *f;

    if (lease->address.s_addr == 0)
        return 0; /* nothing to cache yet */
    if (!ctx->conf.lease_file[0])
        return 0; /* lease DB opted out (plan §6 lease_file: none) */
    snprintf(path, sizeof(path), "%s", ctx->conf.lease_file);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    f = fopen(tmp, "w");
    if (!f) {
        hadc_err("dhcpcore: fopen %s: %s", tmp, strerror(errno));
        return -1;
    }
    fprintf(f, "lease {\n  interface \"%s\";\n  fixed-address %s;\n",
            ctx->conf.interface, inet_ntop(AF_INET, &lease->address, buf, sizeof(buf)));
    if (lease->netmask.s_addr != 0)
        fprintf(f, "  option subnet-mask %s;\n",
                inet_ntop(AF_INET, &lease->netmask, buf, sizeof(buf)));
    if (lease->gateway.s_addr != 0)
        fprintf(f, "  option routers %s;\n",
                inet_ntop(AF_INET, &lease->gateway, buf, sizeof(buf)));
    if (lease->n_dns > 0) {
        fprintf(f, "  option domain-name-servers ");
        for (size_t i = 0; i < lease->n_dns; i++)
            fprintf(f, "%s%s", i ? ", " : "",
                    inet_ntop(AF_INET, &lease->dns[i], buf2, sizeof(buf2)));
        fprintf(f, ";\n");
    }
    if (lease->server_id.s_addr != 0)
        fprintf(f, "  option dhcp-server-identifier %s;\n",
                inet_ntop(AF_INET, &lease->server_id, buf, sizeof(buf)));
    /* Same format the fork's write_client_lease produces (gmtime). */
    static const char *field[3] = { "renew", "rebind", "expire" };
    long long at[3] = { lease->t1_at_utc, lease->t2_at_utc, lease->t3_at_utc };
    for (int i = 0; i < 3; i++) {
        if (at[i] <= 0)
            continue;
        time_t when = (time_t)at[i];
        struct tm tm;
        gmtime_r(&when, &tm);
        fprintf(f, "  %s %d %d/%d/%d %02d:%02d:%02d;\n", field[i], tm.tm_wday,
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
                tm.tm_sec);
    }
    fprintf(f, "}\n");
    fflush(f);
    fsync(fileno(f));
    fclose(f);
    if (rename(tmp, path) != 0) {
        hadc_err("dhcpcore: rename to %s: %s", path, strerror(errno));
        return -1;
    }
    hadc_dbg("dhcpcore: lease file refreshed for %s", path);
    return 0;
}

int hadc_dhcpcore_step(hadc_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}
