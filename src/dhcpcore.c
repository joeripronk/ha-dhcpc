/* DHCP engine adapter (plan §3). Master-only by contract: drives the
 * vendored FreeBSD dhclient core (src/dhcp/) from the daemon event loop.
 * The core exposes its protocol fds (dhcp_core_get_fds) and its earliest
 * timeout (dhcp_core_next_timeout_ms); the daemon registers them with its
 * epoll loop and pumps dispatch_step()/dhcp_core_run_timeouts() when they
 * fire. Reasons come back through dhcp_core_set_hooks and are mapped onto
 * the frozen daemon callbacks. */
#define _GNU_SOURCE

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
    struct timespec mono;
    const struct option_data *dns;

    clock_gettime(CLOCK_MONOTONIC, &mono);
    time_t now = mono.tv_sec;

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
    out->t1_remaining_s = l->renewal > now ? (uint32_t)(l->renewal - now) : 0;
    out->t2_remaining_s = l->rebind > now ? (uint32_t)(l->rebind - now) : 0;
    out->t3_remaining_s = l->expiry > now ? (uint32_t)(l->expiry - now) : 0;
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
    (void)arg;

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

int hadc_dhcpcore_start(hadc_ctx_t *ctx)
{
    char conf[HADC_PATH_MAX + 32];
    int fds[CORE_FDS_MAX];
    int nfds;

    if (ctx->role != HADC_ROLE_MASTER) {
        hadc_dbg("dhcpcore: not started (slaves are passive to DHCP)");
        return 0;
    }

    conf[0] = '\0';
    if (ctx->conf.apply.dns_hook[0] != '\0')
        snprintf(conf, sizeof(conf), "script \"%s\";\n",
                 ctx->conf.apply.dns_hook);
    dhcp_core_set_conf_text(conf);
    dhcp_core_set_hooks(adapter_on_reason, ctx);
    dhcp_core_set_retention(ctx->conf.dhcp.retention != HADC_RETENTION_OFF,
                             ctx->conf.dhcp.rediscover_in_retention ? 1 : 0, 0, 0);
    dhcp_core_set_rate_limit_ms(ctx->conf.dhcp.rate_limit_ms);

    if (dhcp_core_start(ctx->conf.interface, NULL, NULL) != 0) {
        hadc_err("dhcpcore: core start failed");
        return -1;
    }

    for (size_t i = 0; i < ctx->conf.dhcp.n_request_options; i++)
        dhcp_core_add_requested_option(ctx->conf.dhcp.request_options[i]);

    ctx->core_timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (ctx->core_timerfd < 0 ||
        hadc_loop_add(ctx, ctx->core_timerfd, core_timer_ready, 0) != 0) {
        hadc_err("dhcpcore: core timer setup failed");
        return -1;
    }
    nfds = dhcp_core_get_fds(fds, CORE_FDS_MAX);
    for (int i = 0; i < nfds; i++) {
        if (hadc_loop_add(ctx, fds[i], core_fd_ready, 0) != 0) {
            hadc_err("dhcpcore: epoll register fd %d failed", fds[i]);
            return -1;
        }
    }
    core_arm_timer(ctx);

    hadc_info("dhcpcore: engine running on %s (%d fds, retention=%s)",
              ctx->conf.interface, nfds,
              ctx->conf.dhcp.retention == HADC_RETENTION_OFF ? "off" : "on");
    return 0;
}

int hadc_dhcpcore_stop(hadc_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

int hadc_dhcpcore_step(hadc_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}
