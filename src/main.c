/* ha-dhcpc daemon — M1 scaffold (plan §10).
 * Loads the three config files, restores the persisted cluster view,
 * runs one epoll event loop (heartbeat timer + ctl socket + UDP transport).
 * DHCP engine, cluster decisions and netlink application are stubs wired
 * through the frozen M0 interfaces. */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/config.h"
#include "ha-dhcpc/conntrack.h"
#include "ha-dhcpc/ctl.h"
#include "ha-dhcpc/dhcpcore.h"
#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/lease.h"
#include "ha-dhcpc/log.h"
#include "ha-dhcpc/persist.h"
#include "ha-dhcpc/routing.h"
#include "internal.h"
#include "ospf.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <jansson.h>

#ifndef HADC_VERSION
#define HADC_VERSION "dev"
#endif
#ifndef HADC_BUILD_TIME
#define HADC_BUILD_TIME "unknown"
#endif

#define MAX_FDS 16

typedef struct {
    int fd;
    hadc_fd_cb_t cb;
    int flags;
} fd_entry_t;

static fd_entry_t g_fds[MAX_FDS];
static size_t g_nfds;
static hadc_ctx_t g_ctx;


static bool ifname_is_vip_cluster_iface(const hadc_ctx_t *ctx, const char *ifname)
{
    if (!ctx || !ifname || !*ifname)
        return false;
    for (size_t i = 0; i < ctx->conf.cluster.n_ifaces; i++) {
        if (!strcmp(ctx->conf.cluster.ifaces[i].interface, ifname))
            return true;
    }
    return false;
}

void hadc_validate_demote_route_config(hadc_ctx_t *ctx, const char *why)
{
    bool want = ctx->conf.apply.demote_route_via_new_master;
    bool ok = true;
    char reason[128] = "";

    if (!want) {
        ctx->demote_route_via_new_master_active = false;
        ctx->demote_route_via_new_master_invalid = false;
        ctx->demote_route_via_new_master_reason[0] = '\0';
        return;
    }

    if (!ctx->conf.apply.slave_sync_wan) {
        snprintf(reason, sizeof(reason), "requires apply.slave_sync_wan=true");
        ok = false;
    } else if (ctx->conf.ospf.n_interfaces == 0) {
        snprintf(reason, sizeof(reason), "requires at least one ospf.interfaces entry on a non-VIP interface");
        ok = false;
    } else {
        for (size_t i = 0; i < ctx->conf.ospf.n_interfaces; i++) {
            const char *oif = ctx->conf.ospf.interfaces[i];
            if (ifname_is_vip_cluster_iface(ctx, oif)) {
                snprintf(reason, sizeof(reason), "ospf interface %s must not carry VIP/cluster addresses", oif);
                ok = false;
                break;
            }
        }
    }

    if (!ok) {
        ctx->demote_route_via_new_master_active = false;
        ctx->demote_route_via_new_master_invalid = true;
        snprintf(ctx->demote_route_via_new_master_reason, sizeof(ctx->demote_route_via_new_master_reason), "%s", reason);
        hadc_err("demote_route_via_new_master(%s): invalid configuration: %s; behaviour disabled", why ? why : "config", reason);
    } else {
        bool was_invalid = ctx->demote_route_via_new_master_invalid;
        ctx->demote_route_via_new_master_active = true;
        ctx->demote_route_via_new_master_invalid = false;
        ctx->demote_route_via_new_master_reason[0] = '\0';
        if (was_invalid)
            hadc_info("demote_route_via_new_master(%s): configuration now valid; behaviour enabled", why ? why : "config");
        else
            hadc_info("demote_route_via_new_master(%s): enabled (slave_sync_wan and non-VIP OSPF fabric verified)", why ? why : "config");
    }
}

int hadc_loop_add(hadc_ctx_t *ctx, int fd, hadc_fd_cb_t cb, int events)
{
    if (g_nfds >= MAX_FDS || fd < 0)
        return -1;
    g_fds[g_nfds].fd = fd;
    g_fds[g_nfds].cb = cb;
    g_fds[g_nfds].flags = events;
    g_nfds++;
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = fd };
    if (epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        hadc_err("loop: epoll add fd %d: %s", fd, strerror(errno));
        return -1;
    }
    return 0;
}

int hadc_loop_del(hadc_ctx_t *ctx, int fd)
{
    size_t j = 0;
    while (j < g_nfds && g_fds[j].fd != fd)
        j++;
    if (j == g_nfds)
        return -1;
    g_fds[j] = g_fds[--g_nfds];
    if (epoll_ctl(ctx->epfd, EPOLL_CTL_DEL, fd, NULL) != 0) {
        /* The owner may already have closed the fd (Linux drops it from the
         * epoll set automatically), so ENOENT/EBADF is not an error. */
        if (errno != ENOENT && errno != EBADF) {
            hadc_err("loop: epoll del fd %d: %s", fd, strerror(errno));
            return -1;
        }
    }
    return 0;
}

static void heartbeat_fire(hadc_ctx_t *ctx)
{
    hadc_cluster_heartbeat(ctx); /* bidirectional, with lease summary (plan §4) */
}

static void heartbeat_ready(hadc_ctx_t *ctx, int fd)
{
    uint64_t exp;
    (void)!read(fd, &exp, sizeof(exp));
    heartbeat_fire(ctx);
}

static void hb_selfpipe_ready(hadc_ctx_t *ctx, int fd)
{
    (void)fd;
    hadc_cluster_selfpipe_ready(ctx);
}

static void handoff_hold_complete(hadc_ctx_t *ctx, const char *reason);

static void periodic_ready(hadc_ctx_t *ctx, int fd)
{
    uint64_t exp;
    (void)!read(fd, &exp, sizeof(exp));
    if (ctx->handoff_forward_hold) {
        uint64_t now = (uint64_t)hadc_now_ms();
        /* Keep default route and public IP for the full handoff hold (VIPs drop at
         * demotion, or stay assigned-with-ARP-suppressed through the hold when
         * seamless-takeover steering is active); only complete after the hold expires. */
        if (now >= ctx->handoff_hold_until_ms)
            handoff_hold_complete(ctx, "handoff-hold-timeout");
    }
    /* Offload audit/gwping/routing maintenance to the serialized worker so the
     * main loop stays responsive to heartbeats. */
    hadc_maint_post_tick(ctx);
}

static void handoff_hold_complete(hadc_ctx_t *ctx, const char *reason)
{
    if (!ctx->handoff_forward_hold)
        return;
    ctx->handoff_forward_hold = false;
    ctx->handoff_target[0] = '\0';
    ctx->handoff_hold_until_ms = 0;
    /* transition DEMOTING -> SLAVE and apply full slave isolation (egress block) */
    if (ctx->role == HADC_ROLE_DEMOTING) {
        hadc_role_t old = ctx->role;
        ctx->role = HADC_ROLE_SLAVE; /* announce demoted only now */
        hadc_desired_t desired;
        hadc_executor_desired(ctx, &ctx->lease, &desired);
        hadc_executor_apply(ctx, &desired, reason);
        hadc_routing_reconcile(ctx, reason);
        hadc_conntrack_notify_role(ctx, old, ctx->role);
        hadc_info("handoff: hold complete (%s); slave isolation applied", reason);
        /* propagate role/state via heartbeat thread snapshot */
        hadc_persist_save(ctx);
    }
}

static void signal_ready(hadc_ctx_t *ctx, int fd)
{
    struct signalfd_siginfo si;
    (void)!read(fd, &si, sizeof(si));
    if (ctx->role == HADC_ROLE_MASTER || ctx->role == HADC_ROLE_PROMOTING) {
        uint32_t t1, t2, t3;
        hadc_lease_remaining(&ctx->lease, (long long)time(NULL), &t1, &t2, &t3);
        hadc_info("shutdown: role=master lease state=%s renew_in=%us rebind_in=%us expire_in=%us",
                  hadc_lease_state_name(ctx->lease.state), t1, t2, t3);
    }

    bool force = false;
    if (si.ssi_signo == SIGTERM)
        force = (ctx->conf.signal.sigterm_action == HADC_SHUTDOWN_NOW);
    else
        force = (ctx->conf.signal.sigint_action == HADC_SHUTDOWN_NOW);

    if (ctx->conf.n_members == 0) {
        hadc_info("signal %u received; standalone shutdown, leaving service intact", si.ssi_signo);
        ctx->shutting_down = true;
        ctx->running = false;
        return;
    }
    if (hadc_cluster_graceful_active(ctx)) {
        hadc_info("signal %u received; graceful restart active, shutting down without handoff/teardown", si.ssi_signo);
        ctx->shutting_down = true;
        ctx->running = false;
        return;
    }
    if ((ctx->role == HADC_ROLE_MASTER || ctx->role == HADC_ROLE_PROMOTING) && hadc_cluster_handoff(ctx)) {
        hadc_info("signal %u received; handed off before shutdown", si.ssi_signo);
        ctx->shutting_down = true;
        ctx->running = false;
        return;
    }
    if (force) {
        hadc_warn("signal %u received; no live peer available for handoff, shutting down without handoff", si.ssi_signo);
        ctx->shutting_down = true;
        ctx->running = false;
        return;
    }
    hadc_warn("signal %u received; no live peer available for handoff, shutdown cancelled", si.ssi_signo);
}

/* DHCP engine callbacks (dhcpcore adapter -> daemon). */

static void cb_retention(void *arg, bool entered);

/* Master-side gateway MAC cache (plan §4 sync unit): learn the gateway's
 * lladdr from our own resolved neighbor entry so a promoted node does not
 * have to re-discover it with ARP. 1 = newly cached. */
static int cache_gw_mac(hadc_ctx_t *ctx)
{
    uint8_t mac[HADC_MAC_LEN];

    if (!(ctx->role == HADC_ROLE_MASTER || ctx->role == HADC_ROLE_PROMOTING) || ctx->lease.gateway.s_addr == 0)
        return 0;
    if (hadc_executor_observe_gw_mac(ctx, mac) != 0)
        return 0;
    if (ctx->lease.gw_mac_valid && hadc_mac_equal(ctx->lease.gw_mac, mac))
        return 0;
    memcpy(ctx->lease.gw_mac, mac, sizeof(mac));
    ctx->lease.gw_mac_valid = true;
    hadc_info("lease: gateway %s lladdr %02x:%02x:%02x:%02x:%02x:%02x cached in "
              "cluster state",
              inet_ntoa(*(struct in_addr *)&ctx->lease.gateway), mac[0], mac[1],
              mac[2], mac[3], mac[4], mac[5]);
    return 1;
}

static void abort_tcp_on_newip(hadc_ctx_t *ctx, const struct in_addr *old_addr)
{
    int fd;
    int destroyed = 0, failed = 0, truncated = 0;
    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 r;
    } req;
    char buf[8192];
    struct inet_diag_sockid matches[256];
    size_t nmatch = 0;

    if (!ctx->conf.apply.abort_tcp_on_newip || !old_addr || old_addr->s_addr == 0)
        return;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) {
        hadc_warn("newip: cannot open sock_diag socket: %s", strerror(errno));
        return;
    }

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(req.r));
    req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.r.sdiag_family = AF_INET;
    req.r.sdiag_protocol = IPPROTO_TCP;
    req.r.idiag_states = (1u << TCP_ESTABLISHED) | (1u << TCP_SYN_SENT) |
                         (1u << TCP_SYN_RECV) | (1u << TCP_FIN_WAIT1) |
                         (1u << TCP_FIN_WAIT2) | (1u << TCP_TIME_WAIT) |
                         (1u << TCP_CLOSE) | (1u << TCP_CLOSE_WAIT) |
                         (1u << TCP_LAST_ACK) | (1u << TCP_LISTEN) |
                         (1u << TCP_CLOSING);

    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        hadc_warn("newip: sock_diag dump request failed: %s", strerror(errno));
        close(fd);
        return;
    }

    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            hadc_warn("newip: sock_diag dump failed: %s", strerror(errno));
            close(fd);
            return;
        }
        if (n == 0)
            break;
        for (struct nlmsghdr *nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, (unsigned)n);
             nlh = NLMSG_NEXT(nlh, n)) {
            struct inet_diag_msg *d;

            if (nlh->nlmsg_type == NLMSG_DONE)
                goto dump_done;
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = NLMSG_DATA(nlh);
                hadc_warn("newip: sock_diag dump error: %s", strerror(-e->error));
                close(fd);
                return;
            }
            d = NLMSG_DATA(nlh);
            if (d->idiag_family != AF_INET)
                continue;
            if (memcmp(d->id.idiag_src, old_addr, 4) != 0)
                continue;
            if (nmatch < sizeof(matches) / sizeof(matches[0]))
                matches[nmatch++] = d->id;
            else
                truncated++;
        }
    }

dump_done:
    if (nmatch == 0 && !truncated) {
        close(fd);
        hadc_info("newip: no TCP sockets bound to %s", inet_ntoa(*old_addr));
        return;
    }

    for (size_t i = 0; i < nmatch; i++) {
        struct {
            struct nlmsghdr nlh;
            struct inet_diag_req_v2 r;
        } del;
        ssize_t n;

        memset(&del, 0, sizeof(del));
        del.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(del.r));
        del.nlh.nlmsg_type = SOCK_DESTROY;
        del.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        del.r.sdiag_family = AF_INET;
        del.r.sdiag_protocol = IPPROTO_TCP;
        del.r.id = matches[i];
        if (send(fd, &del, del.nlh.nlmsg_len, 0) < 0) {
            failed++;
            continue;
        }
        for (;;) {
            n = recv(fd, buf, sizeof(buf), 0);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                failed++;
                goto destroy_done;
            }
            if (n == 0) {
                failed++;
                goto destroy_done;
            }
            {
                bool got_ack = false;
                for (struct nlmsghdr *nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, (unsigned)n);
                     nlh = NLMSG_NEXT(nlh, n)) {
                    if (nlh->nlmsg_type == NLMSG_ERROR) {
                        struct nlmsgerr *e = NLMSG_DATA(nlh);
                        if (e->error == 0)
                            destroyed++;
                        else
                            failed++;
                        got_ack = true;
                    }
                }
                if (got_ack)
                    break;
            }
        }
    }
destroy_done:
    close(fd);
    if (truncated)
        hadc_warn("newip: too many TCP sockets bound to %s; aborted %d, failed %d, skipped %d",
                  inet_ntoa(*old_addr), destroyed, failed, truncated);
    else
        hadc_info("newip: aborted TCP sockets bound to %s (destroyed=%d failed=%d)",
                  inet_ntoa(*old_addr), destroyed, failed);
}

static void cb_lease_update(void *arg, const hadc_lease_t *lease)
{
    hadc_ctx_t *ctx = arg;
    hadc_desired_t desired;

    if (lease != NULL) {
        struct in_addr old = ctx->newip_old_addr;
        bool pending = ctx->newip_pending;
        bool retention = ctx->lease.retention_active;

        hadc_cluster_lock();
        ctx->lease = *lease;
        ctx->lease.retention_active = retention;
        hadc_cluster_unlock();
        {
            uint32_t t1, t3;
            hadc_lease_remaining(&ctx->lease, (long long)time(NULL), &t1, NULL, &t3);
            hadc_info("lease update v%llu state=%s addr=%s t1=%us t3=%us",
                      (unsigned long long)ctx->lease.version,
                      hadc_lease_state_name(ctx->lease.state),
                      inet_ntoa(*(struct in_addr *)&ctx->lease.address), t1, t3);
        }
        hadc_executor_desired(ctx, &ctx->lease, &desired);
        hadc_executor_apply(ctx, &desired,
                            lease->state == HADC_LEASE_RENEW ? HADC_REASON_RENEW
                            : lease->state == HADC_LEASE_REBIND ? HADC_REASON_REBIND
                                                                : HADC_REASON_BOUND);
        ctx->acked_version = ctx->lease.version;

        if (pending) {
            if (old.s_addr != 0 && old.s_addr != ctx->lease.address.s_addr)
                abort_tcp_on_newip(ctx, &old);
            else if (old.s_addr != 0)
                hadc_info("newip: new lease kept address %s; no TCP abort needed",
                          inet_ntoa(ctx->lease.address));
            ctx->newip_pending = false;
            ctx->newip_old_addr.s_addr = 0;
        }
    } else if (ctx->conf.dhcp.retention != HADC_RETENTION_OFF &&
               ctx->lease.address.s_addr != 0) {
        /* Retention beats expiry (plan §5): the engine gave up (FAIL/EXPIRE)
         * but we have a last-known-good cached lease — keep it applied. */
        cb_retention(arg, true);
        return;
    } else {
        hadc_warn("lease gone (EXPIRE/FAIL); no desired state");
        hadc_cluster_lock();
        memset(&ctx->lease, 0, sizeof(ctx->lease));
        hadc_cluster_unlock();
        if (ctx->newip_pending) {
            ctx->newip_pending = false;
            ctx->newip_old_addr.s_addr = 0;
        }
        hadc_executor_desired(ctx, &ctx->lease, &desired);
        hadc_executor_apply(ctx, &desired, HADC_REASON_EXPIRE);
    }
    ctx->acked_version = ctx->lease.version;
    cache_gw_mac(ctx);
    hadc_routing_reconcile(ctx, lease ? "lease-update" : "lease-lost");
    if (ctx->role == HADC_ROLE_SLAVE || ctx->role == HADC_ROLE_DEMOTING) {
        hadc_desired_t rd;
        hadc_executor_desired(ctx, &ctx->lease, &rd);
        hadc_executor_apply(ctx, &rd, "ROUTING-RECONCILE");
    }
    hadc_cluster_push_state(ctx, &ctx->lease); /* master-only (plan §4) */
    hadc_persist_save(ctx);
}

static void cb_retention(void *arg, bool entered)
{
    hadc_ctx_t *ctx = arg;
    hadc_desired_t desired;

    hadc_info("retention %s (plan §5)", entered ? "enter" : "exit");
    hadc_cluster_lock();
    ctx->lease.retention_active = entered;
    if (entered)
        ctx->lease.state = HADC_LEASE_RETAINED;
    else if (ctx->lease.state == HADC_LEASE_RETAINED)
        ctx->lease.state = HADC_LEASE_BOUND;
    hadc_cluster_unlock();
    hadc_executor_desired(ctx, &ctx->lease, &desired);
    hadc_executor_apply(ctx, &desired, entered ? "RETAINED-ENTER" : "RETAINED-EXIT");
    hadc_routing_reconcile(ctx, entered ? "retention-enter" : "retention-exit");
    ctx->acked_version = ctx->lease.version;
    hadc_cluster_push_state(ctx, &ctx->lease);
    hadc_persist_save(ctx);
}

static void cb_carrier_return(void *arg)
{
    hadc_ctx_t *ctx = arg;
    hadc_desired_t desired;

    hadc_info("carrier return; reapplying desired state");
    hadc_executor_desired(ctx, &ctx->lease, &desired);
    hadc_executor_apply(ctx, &desired, "CARRIER-RETURN");
}

/* Role transitions (ctl/cluster-driven, plan §4): the engine runs only on the
 * master; a promoted node resumes renew-only on the synced lease and claims the
 * cluster addresses. */
static void cb_role_change(void *arg, hadc_role_t old_role, hadc_role_t new_role)
{
    hadc_ctx_t *ctx = arg;
    hadc_desired_t desired;

    if (old_role == new_role)
        return;
    if (new_role == HADC_ROLE_PROMOTING) {
        ctx->promotion_pending = true;
        hadc_executor_link_up(ctx->conf.interface); /* the master must speak DHCP */
        hadc_lease_prepare_for_promotion(&ctx->lease);
        {
            uint32_t t1, t2, t3;
            hadc_lease_remaining(&ctx->lease, (long long)time(NULL), &t1, &t2, &t3);
            hadc_info("promotion: lease state=%s renew_in=%us rebind_in=%us expire_in=%us (setup in progress)",
                      hadc_lease_state_name(ctx->lease.state), t1, t2, t3);
        }
        /* Promote dataplane but do NOT announce role=master yet: apply lease/public
         * address and routes, then VIPs, then GARP burst; only after that mark ready. */
        hadc_executor_desired(ctx, &ctx->lease, &desired);
        desired.cluster_addrs_present = false;
        hadc_executor_apply(ctx, &desired, "PROMOTE");
        hadc_routing_reconcile(ctx, "promote");
        desired.cluster_addrs_present = true;
        hadc_executor_apply(ctx, &desired, "PROMOTE-VIPS");
        hadc_executor_announce_cluster(ctx); /* configurable burst; switches L2 to us */
        hadc_dhcpcore_start(ctx);
        /* announce ready: heartbeats now report master */
        hadc_cluster_lock();
        if (ctx->role == HADC_ROLE_PROMOTING)
            ctx->role = HADC_ROLE_MASTER;
        ctx->promotion_pending = false;
        hadc_cluster_unlock();
        hadc_info("promotion: setup complete, announced master");
        /* delay gwping to avoid probe traffic/mac flips during handoff */
        if (ctx->conf.apply.gateway_probe && ctx->conf.apply.gateway_probe_start_delay_ms > 0) {
            ctx->gwping_start_after_ms = (uint64_t)hadc_now_ms() + ctx->conf.apply.gateway_probe_start_delay_ms;
            hadc_info("gwping: start delayed %ums after promote", ctx->conf.apply.gateway_probe_start_delay_ms);
        } else {
            ctx->gwping_start_after_ms = 0;
            hadc_gwping_start(ctx);
        }
    } else if (new_role == HADC_ROLE_DEMOTING) {
        /* Controlled handoff: keep public IP/default route and forward traffic
         * (clients may still send to our MAC); defer nft egress block until the new
         * master is announced ready via heartbeat or timeout. VIPs drop at demotion,
         * except with seamless-takeover steering where they stay assigned (ARP-reply
         * suppression active) until the hold completes. */
        if (old_role == HADC_ROLE_MASTER || old_role == HADC_ROLE_PROMOTING) {
            hadc_gwping_stop(ctx);
            hadc_dhcpcore_stop(ctx);
        }
        ctx->handoff_forward_hold = true;
        ctx->handoff_hold_until_ms = (uint64_t)hadc_now_ms() + ctx->conf.apply.handoff_hold_ms;
        snprintf(ctx->handoff_target, sizeof(ctx->handoff_target), "%s", ctx->conf.designated_master);
        hadc_info("demotion: entering handoff hold to %s for up to %ums (forwarding kept, egress block deferred), lease state=%s",
                  ctx->handoff_target, ctx->conf.apply.handoff_hold_ms,
                  hadc_lease_state_name(ctx->lease.state));
        hadc_executor_desired(ctx, &ctx->lease, &desired);
        /* Seamless takeover: when steering is active the VIPs stay assigned for the
         * whole hold (ARP replies suppressed, no VIP-source traffic) and are removed
         * only when the hold completes; otherwise they drop at demotion as before. */
        if (!desired.vip_hold_suppress)
            desired.cluster_addrs_present = false;
        /* keep WAN public IP and default route, no nft egress block yet */
        if (ctx->lease.address.s_addr != 0 && ctx->lease.state != HADC_LEASE_NONE) {
            desired.present = true;
            desired.link_state = 1;
            desired.slave_nft_block = false;
            desired.gateway = ctx->lease.gateway; /* keep forwarding path */
            desired.add_routes = ctx->conf.apply.routes;
        }
        desired.backup_route = false;
        hadc_executor_apply(ctx, &desired, "DEMOTE-VIPS-HOLD");
        hadc_routing_reconcile(ctx, "demote-hold");
    } else {
        /* SLAVE or other: ensure not holding */
        ctx->handoff_forward_hold = false;
        if (old_role == HADC_ROLE_MASTER || old_role == HADC_ROLE_PROMOTING) {
            hadc_gwping_stop(ctx);
            hadc_dhcpcore_stop(ctx);
        }
        hadc_executor_desired(ctx, &ctx->lease, &desired);
        desired.cluster_addrs_present = false;
        if (ctx->lease.address.s_addr != 0 && ctx->lease.state != HADC_LEASE_NONE) {
            desired.present = true;
            desired.link_state = 1;
            desired.slave_nft_block = false;
            desired.gateway.s_addr = 0;
        }
        hadc_executor_apply(ctx, &desired, "DEMOTE-VIPS");
        hadc_routing_reconcile(ctx, "demote");
        hadc_executor_desired(ctx, &ctx->lease, &desired);
        hadc_executor_apply(ctx, &desired, "DEMOTE");
    }
    hadc_conntrack_notify_role(ctx, old_role, ctx->role);
    ctx->acked_version = ctx->lease.version;
    hadc_persist_save(ctx);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [--conf path] [--local-conf path] [--persist path] [--oneshot]\n"
            "       %s ctl|c <cmd> [--conf path] [--local-conf path]\n"
            "       %s status|s [cluster|c|ip|i|ospf|o [routes|r|neighbors|n]] [detailed|d]\n"
            "       %s -v|--version\n"
            "ctl cmds (unambiguous prefixes ok): status|s promote|p demote|d update|u "
            "renew|r newip|n graceful-restart|g [enable|e disable|d] conntrack|c resync shutdown [now]|kill\n",
            argv0, argv0, argv0, argv0);
}

/* Client mode: ha-dhcpc [conf paths] ctl promote|demote|status|update|renew|newip [id] (plan §3). */
static int ctl_client(const char *conf_path, const char *local_path, const char *cmd_line)
{
    hadc_conf_t conf;
    char err[256];
    char line[256];
    char reply[4096];

    if (hadc_config_load(conf_path, local_path, &conf, err, sizeof(err)) != 0) {
        fprintf(stderr, "ha-dhcpc ctl: %s\n", err);
        return 1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", conf.ctl_socket);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "ha-dhcpc ctl: connect %s: %s\n", conf.ctl_socket, strerror(errno));
        return 1;
    }
    snprintf(line, sizeof(line), "%s\n", cmd_line);
    if (write(fd, line, strlen(line)) != (ssize_t)strlen(line)) {
        fprintf(stderr, "ha-dhcpc ctl: write: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    ssize_t n = read(fd, reply, sizeof(reply) - 1);
    close(fd);
    if (n <= 0) {
        fprintf(stderr, "ha-dhcpc ctl: no reply from daemon\n");
        return 1;
    }
    reply[n] = '\0';
    fputs(reply, stdout);
    return 0;
}

/* Human-readable status: ha-dhcpc status|s [cluster|c|ip|i|ospf|o
 * [routes|r|neighbors|n]] [detailed|d]. Asks the daemon for the standard
 * status JSON and renders the selected section(s). */

static const char *jsget(json_t *o, const char *key)
{
    json_t *v = o ? json_object_get(o, key) : NULL;
    return json_is_string(v) ? json_string_value(v) : NULL;
}

static json_t *jobj(json_t *o, const char *key)
{
    json_t *v = o ? json_object_get(o, key) : NULL;
    return json_is_object(v) ? v : NULL;
}

static json_t *jarr(json_t *o, const char *key)
{
    json_t *v = o ? json_object_get(o, key) : NULL;
    return json_is_array(v) ? v : NULL;
}

static int jbool(json_t *o, const char *key, int dflt)
{
    json_t *v = o ? json_object_get(o, key) : NULL;
    if (json_is_boolean(v))
        return (int)json_boolean_value(v);
    return dflt;
}

static long long jint(json_t *o, const char *key, long long dflt)
{
    json_t *v = o ? json_object_get(o, key) : NULL;
    return json_is_integer(v) ? (long long)json_integer_value(v) : dflt;
}

static const char *yns(int b)
{
    return b < 0 ? "unknown" : (b ? "yes" : "no");
}

static const char *str_or_null(const char *s)
{
    return (s && s[0]) ? s : "n/a";
}

static void r_ip(json_t *st, bool detail)
{
    json_t *dhcp = jobj(st, "dhcp");
    json_t *gwp = jobj(st, "gwping");
    json_t *rs = jobj(jobj(st, "routing"), "state");
    const char *gwp_state = "off";
    long long t1 = jint(dhcp, "t1_remaining_s", -1);
    long long t2 = jint(dhcp, "t2_remaining_s", -1);
    long long t3 = jint(dhcp, "t3_remaining_s", -1);

    if (gwp) {
        if (jbool(gwp, "enabled", 0))
            gwp_state = jbool(gwp, "unreachable", 0) ? "UNREACHABLE" : "reachable";
    }
    printf("ip       public %s  dhcp %s lease %s gw %s  gwping %s  renew in %llds\n",
           str_or_null(jsget(rs, "public_ip32")), str_or_null(jsget(dhcp, "state")),
           str_or_null(jsget(dhcp, "address")), str_or_null(jsget(dhcp, "gateway")), gwp_state, t1);
    if (detail && dhcp) {
        printf("         renew in %llds  rebind in %llds  expire in %llds  server %s  retention %s  lease v%lld\n",
               t1, t2, t3, str_or_null(jsget(dhcp, "server_id")),
               yns(jbool(st, "retention", -1)), jint(st, "lease_version", -1));
        json_t *dns = jarr(dhcp, "dns");
        if (dns && json_array_size(dns) > 0) {
            printf("         dns");
            for (size_t i = 0; i < json_array_size(dns); i++) {
                json_t *e = json_array_get(dns, i);
                printf(" %s", json_is_string(e) ? json_string_value(e) : "n/a");
            }
            printf("\n");
        }
    }
}

static void r_cluster(json_t *st, bool detail)
{
    json_t *members = jarr(st, "members");
    size_t n = members ? json_array_size(members) : 0;
    const char *self = jsget(st, "self");
    size_t alive = 0;

    for (size_t i = 0; i < n; i++) {
        json_t *m = json_array_get(members, i);
        if (jsget(m, "id") && self && !strcmp(jsget(m, "id"), self))
            alive++; /* this node: alive by definition */
        else if (jbool(m, "alive", 0))
            alive++;
    }
    printf("cluster  role %s  self %s  master %s  members %zu (%zu alive)\n",
           str_or_null(jsget(st, "role")), str_or_null(jsget(st, "self")),
           str_or_null(jsget(st, "master")), n, alive);
    if (!detail)
        return;
    for (size_t i = 0; i < n; i++) {
        json_t *m = json_array_get(members, i);
        bool is_self = jsget(m, "id") && self && !strcmp(jsget(m, "id"), self);
        if (is_self) {
            /* Peer-view columns have no entry for this node; show what this
             * node actually knows about itself. */
            printf("         %s %s alive ack v%lld  role-view %s  master-view %s  conf %s (self)\n",
                   str_or_null(jsget(m, "id")), str_or_null(jsget(m, "sync_address")),
                   jint(st, "lease_version", -1), str_or_null(jsget(st, "role")),
                   str_or_null(jsget(st, "master")), str_or_null(jsget(st, "conf_sha256")));
            continue;
        }
        printf("         %s %s %s ack v%lld  role-view %s  master-view %s  conf %s\n",
               str_or_null(jsget(m, "id")), str_or_null(jsget(m, "sync_address")),
               jbool(m, "alive", 0) ? "alive" : "DEAD", jint(m, "acked_version", -1),
               str_or_null(jsget(m, "role")), str_or_null(jsget(m, "master_view")),
               str_or_null(jsget(m, "conf_sha256")));
    }
    json_t *gr = jobj(st, "graceful_restart");
    printf("         graceful-restart %s until %lldms  timers: heartbeat %lldms election %lldms\n",
           yns(jbool(gr, "active", -1)), jint(gr, "until_ms", -1),
           jint(jobj(st, "timers"), "heartbeat_ms", -1), jint(jobj(st, "timers"), "election_deadline_ms", -1));
    json_t *dm = jobj(st, "demote_route_via_new_master");
    if (dm)
        printf("         steered-takeover configured=%s active=%s invalid=%s reason=%s\n",
               yns(jbool(dm, "configured", -1)), yns(jbool(dm, "active", -1)), yns(jbool(dm, "invalid", -1)),
               str_or_null(jsget(dm, "reason")));
    json_t *addrs = jarr(st, "cluster_addresses");
    for (size_t i = 0; addrs && i < json_array_size(addrs); i++) {
        json_t *ci = json_array_get(addrs, i);
        json_t *list = jarr(ci, "addresses");
        for (size_t j = 0; list && j < json_array_size(list); j++) {
            json_t *e = json_array_get(list, j);
            printf("         vip %s on %s (owned %s)\n",
                   str_or_null(json_is_string(e) ? json_string_value(e) : NULL),
                   str_or_null(jsget(ci, "interface")), yns(jbool(ci, "owned", -1)));
        }
    }
}

static void r_ospf_neighbors(json_t *st, bool detail)
{
    json_t *ospf = jobj(jobj(st, "routing"), "ospf");
    json_t *list = jarr(ospf, "neighbor_list");
    size_t n = list ? json_array_size(list) : 0;

    if (!ospf)
        return;
    printf("ospf     neighbors %lld/%lld 2-way (lsdb %lld self + %lld other = %lld)\n",
           jint(ospf, "neighbors_2way", -1), jint(ospf, "neighbors", -1),
           jint(ospf, "lsdb_self", -1), jint(ospf, "lsdb_other", -1), jint(ospf, "lsdb_total", -1));
    if (!detail) {
        /* Minimal: one compressed line, but never hide a non-full neighbor. */
        size_t full = 0;
        for (size_t i = 0; i < n; i++)
            if (jsget(json_array_get(list, i), "state") &&
                !strcmp(jsget(json_array_get(list, i), "state"), "full"))
                full++;
        if (n == 0)
            return;
        if (full == n) {
            printf("         %zu neighbors, all full\n", n);
            return;
        }
        for (size_t i = 0; i < n; i++) {
            json_t *nb = json_array_get(list, i);
            const char *state = jsget(nb, "state");
            if (state && strcmp(state, "full") == 0)
                continue;
            printf("         %s %s %s dead_in %llds\n", str_or_null(jsget(nb, "router_id")),
                   str_or_null(jsget(nb, "ip")), str_or_null(state), jint(nb, "dead_in", -1));
        }
        return;
    }
    for (size_t i = 0; i < n; i++) {
        json_t *nb = json_array_get(list, i);
        printf("         %s %s %s dead_in %llds\n", str_or_null(jsget(nb, "router_id")),
               str_or_null(jsget(nb, "ip")), str_or_null(jsget(nb, "state")), jint(nb, "dead_in", -1));
    }
}

static void r_ospf_routes(json_t *st, bool detail)
{
    json_t *ospf = jobj(jobj(st, "routing"), "ospf");
    json_t *list = jarr(ospf, "learned_prefixes");
    json_t *state = jobj(jobj(st, "routing"), "state");
    json_t *origins = state ? jarr(state, "originated_prefixes") : NULL;
    size_t n = list ? json_array_size(list) : 0;
    size_t m = origins ? json_array_size(origins) : 0;

    if (!ospf)
        return;
    printf("ospf     routes %zu learned, %zu advertised\n", n, m);
    for (size_t i = 0; i < m; i++) {
        json_t *p = json_array_get(origins, i);
        printf("         %s/%lld (advertised by self)\n", str_or_null(jsget(p, "prefix")),
               jint(p, "prefixlen", -1));
    }
    for (size_t i = 0; i < n; i++) {
        json_t *p = json_array_get(list, i);
        const char *prefix = jsget(p, "prefix");
        bool is_default = prefix && !strcmp(prefix, "0.0.0.0");
        if (detail || is_default)
            printf("         %s/%lld via %s (origin %s, %s, lsa %lld)\n", str_or_null(prefix),
                   jint(p, "prefixlen", -1), str_or_null(jsget(p, "nexthop")),
                   str_or_null(jsget(p, "origin")), str_or_null(jsget(p, "source")), jint(p, "lsa_type", -1));
    }
}

static int status_client(const char *conf_path, const char *local_path,
    const char *section, const char *sub, bool detail)
{
    hadc_conf_t conf;
    char err[256];
    const char *line = "status\n";
    char buf[262144];
    ssize_t total = 0;

    if (hadc_config_load(conf_path, local_path, &conf, err, sizeof(err)) != 0) {
        fprintf(stderr, "ha-dhcpc status: %s\n", err);
        return 1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", conf.ctl_socket);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "ha-dhcpc status: connect %s: %s\n", conf.ctl_socket, strerror(errno));
        return 1;
    }
    if (write(fd, line, strlen(line)) != (ssize_t)strlen(line)) {
        fprintf(stderr, "ha-dhcpc status: write: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    for (;;) {
        ssize_t n = read(fd, buf + total, sizeof(buf) - (size_t)total - 1);
        if (n <= 0)
            break;
        total += n;
        if (total >= (ssize_t)sizeof(buf) - 1)
            break;
    }
    close(fd);
    if (total <= 0) {
        fprintf(stderr, "ha-dhcpc status: no reply from daemon\n");
        return 1;
    }
    buf[total] = '\0';
    json_error_t jerr;
    json_t *st = json_loads(buf, 0, &jerr);
    if (!st) {
        fprintf(stderr, "ha-dhcpc status: unparsable reply: %s\n", jerr.text);
        return 1;
    }
    if (!section) {
        r_ip(st, detail);
        r_cluster(st, detail);
        r_ospf_neighbors(st, detail);
        r_ospf_routes(st, detail);
    } else if (!strcmp(section, "ip")) {
        r_ip(st, detail);
    } else if (!strcmp(section, "cluster")) {
        r_cluster(st, detail);
    } else if (!strcmp(section, "ospf")) {
        if (!sub || !strcmp(sub, "neighbors"))
            r_ospf_neighbors(st, detail);
        if (!sub || !strcmp(sub, "routes"))
            r_ospf_routes(st, detail);
    }
    json_decref(st);
    return 0;
}

static bool status_tok(const char *t, const char *full, const char *abbr)
{
    return !strcmp(t, full) || !strcmp(t, abbr);
}

/* Resolve unambiguous literal prefixes of ctl commands (and of the fixed
 * arguments of graceful-restart/conntrack); anything else passes through to
 * the daemon unchanged. */
static const char *ctl_resolve(const char *tok, const char *cmd)
{
    static const char *cmds[] = {"promote", "demote", "status", "update", "renew",
                                 "newip", "graceful-restart", "conntrack", "shutdown", "kill"};
    static const char *gr_args[] = {"enable", "disable", "on", "off", "cancel"};
    static const char *ct_args[] = {"resync"};
    static const char *sd_args[] = {"now", "force"};
    const char **set = cmds;
    size_t n = sizeof(cmds) / sizeof(cmds[0]);
    const char *match = NULL;
    size_t tl = strlen(tok);

    if (cmd && !strcmp(cmd, "graceful-restart")) {
        set = gr_args;
        n = sizeof(gr_args) / sizeof(gr_args[0]);
    } else if (cmd && !strcmp(cmd, "conntrack")) {
        set = ct_args;
        n = sizeof(ct_args) / sizeof(ct_args[0]);
    } else if (cmd && (!strcmp(cmd, "shutdown") || !strcmp(cmd, "kill"))) {
        set = sd_args;
        n = sizeof(sd_args) / sizeof(sd_args[0]);
    }
    for (size_t i = 0; i < n; i++)
        if (!strcmp(tok, set[i]))
            return set[i];
    for (size_t i = 0; i < n; i++)
        if (tl > 0 && tl < strlen(set[i]) && !strncmp(tok, set[i], tl)) {
            if (match)
                return tok; /* ambiguous prefix: pass through */
            match = set[i];
        }
    return match ? match : tok;
}

int main(int argc, char **argv)
{
    const char *conf_path = "/etc/ha-dhcpc/ha-dhcpc.conf";
    const char *local_path = "/etc/ha-dhcpc/ha-dhcpc-local.conf";
    const char *persist_path = NULL; /* default: state.json next to the config */
    bool oneshot = false;
    hadc_ctx_t *ctx = &g_ctx;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
            printf("ha-dhcpc %s (built %s)\n", HADC_VERSION, HADC_BUILD_TIME);
            return 0;
        }
    }
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--conf") && i + 1 < argc) {
            conf_path = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "--local-conf") && i + 1 < argc) {
            local_path = argv[++i];
            continue;
        }
        if (status_tok(argv[i], "ctl", "c") && i + 1 < argc) {
            char cmd[256] = "";
            const char *resolved_cmd = NULL;
            for (int j = i + 1; j < argc; j++) {
                const char *tok = argv[j];
                if (j == i + 1) {
                    resolved_cmd = ctl_resolve(tok, NULL);
                    tok = resolved_cmd;
                } else if (j == i + 2 && resolved_cmd &&
                           (!strcmp(resolved_cmd, "graceful-restart") ||
                            !strcmp(resolved_cmd, "conntrack")))
                    tok = ctl_resolve(tok, resolved_cmd);
                if (cmd[0])
                    strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
                strncat(cmd, tok, sizeof(cmd) - strlen(cmd) - 1);
            }
            return ctl_client(conf_path, local_path, cmd);
        }
        if (status_tok(argv[i], "status", "s")) {
            const char *section = NULL, *sub = NULL;
            bool detail = false;
            for (int j = i + 1; j < argc; j++) {
                if (status_tok(argv[j], "detailed", "d"))
                    detail = true;
                else if (!section && status_tok(argv[j], "summary", "s"))
                    ; /* full summary: no specific section */
                else if (!section && status_tok(argv[j], "cluster", "c"))
                    section = "cluster";
                else if (!section && status_tok(argv[j], "ip", "i"))
                    section = "ip";
                else if (!section && status_tok(argv[j], "ospf", "o"))
                    section = "ospf";
                else if (section && !sub && !strcmp(section, "ospf") &&
                         status_tok(argv[j], "routes", "r"))
                    sub = "routes";
                else if (section && !sub && !strcmp(section, "ospf") &&
                         status_tok(argv[j], "neighbors", "n"))
                    sub = "neighbors";
                else {
                    fprintf(stderr, "ha-dhcpc status: bad argument '%s'\n", argv[j]);
                    return 1;
                }
            }
            return status_client(conf_path, local_path, section, sub, detail);
        }
    }

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version"))
            continue;
        if (!strcmp(argv[i], "--conf") && i + 1 < argc)
            conf_path = argv[++i];
        else if (!strcmp(argv[i], "--local-conf") && i + 1 < argc)
            local_path = argv[++i];
        else if (!strcmp(argv[i], "--persist") && i + 1 < argc)
            persist_path = argv[++i];
        else if (!strcmp(argv[i], "--oneshot"))
            oneshot = true;
        else {
            usage(argv[0]);
            return 2;
        }
    }

    /* Default state file: next to the shared config file (plan §3/§6). */
    char persist_default[PATH_MAX];
    if (!persist_path) {
        char dir[PATH_MAX];
        snprintf(dir, sizeof(dir), "%s", conf_path); /* conf_path may be a literal */
        char *slash = strrchr(dir, '/');
        if (slash) {
            *slash = '\0';
            snprintf(persist_default, sizeof(persist_default), "%s/state.json", dir);
        } else {
            snprintf(persist_default, sizeof(persist_default), "/var/lib/ha-dhcpc/state.json");
        }
        persist_path = persist_default;
    }

    char err[512];
    if (hadc_config_load(conf_path, local_path, &ctx->conf, err, sizeof(err))) {
        hadc_err("config: %s", err);
        return 1;
    }
    if (hadc_config_identity_check(&ctx->conf, err, sizeof(err))) {
        hadc_err("%s", err);
        return 1;
    }
    hadc_log_set_level(ctx->conf.loglevel);

    /* Initial role: obey persisted view, else the designated master in the
     * shared config. */
    hadc_persist_init(ctx, persist_path);
    hadc_persist_view_t pv;
    hadc_persist_load(ctx, &pv);
    ctx->role = pv.found ? pv.role
                         : (!strcmp(ctx->conf.designated_master, ctx->conf.self)
                                ? HADC_ROLE_MASTER
                                : HADC_ROLE_SLAVE);

    if (pv.found) {
        /* Runtime role changes are persisted; the shared config's
         * designated_master is only the cold-start seed. */
        if (ctx->role == HADC_ROLE_MASTER)
            snprintf(ctx->conf.designated_master, sizeof(ctx->conf.designated_master),
                     "%.*s", (int)sizeof(ctx->conf.designated_master) - 1, ctx->conf.self);
        else if (pv.master_id[0])
            snprintf(ctx->conf.designated_master, sizeof(ctx->conf.designated_master),
                     "%.*s", (int)sizeof(ctx->conf.designated_master) - 1, pv.master_id);
        /* startup restore: runs before the heartbeat thread spawns, no lock needed */
        ctx->lease = pv.lease;
        ctx->lease.version = pv.lease_version;
        ctx->acked_version = pv.acked_version;
        ctx->graceful_restart_until_ms = pv.graceful_restart_until_ms;
        ctx->persist_ospf_lsas = pv.ospf_lsas; /* ownership moves to ctx/ospf */
        ctx->persist_ospf_seq = pv.ospf_seq;
        char a[64], nm[64], gw[64];
        inet_ntop(AF_INET, &ctx->lease.address, a, sizeof(a));
        inet_ntop(AF_INET, &ctx->lease.netmask, nm, sizeof(nm));
        inet_ntop(AF_INET, &ctx->lease.gateway, gw, sizeof(gw));
        {
            uint32_t t1, t2, t3;
            hadc_lease_remaining(&ctx->lease, (long long)time(NULL), &t1, &t2, &t3);
            hadc_info("persist: restored role=%s lease_version=%llu state=%s addr=%s "
                      "mask=%s gateway=%s dns=%zu t1=%us t2=%us t3=%us acked=%llu",
                      ctx->role == HADC_ROLE_MASTER ? "master" : "slave",
                      (unsigned long long)pv.lease_version, hadc_lease_state_name(ctx->lease.state),
                      a, nm, gw, ctx->lease.n_dns, t1, t2, t3,
                      (unsigned long long)ctx->acked_version);
        }
    }

    char macstr[32];
    snprintf(macstr, sizeof(macstr), "%02x:%02x:%02x:%02x:%02x:%02x", ctx->conf.master_mac[0],
             ctx->conf.master_mac[1], ctx->conf.master_mac[2], ctx->conf.master_mac[3],
             ctx->conf.master_mac[4], ctx->conf.master_mac[5]);
    hadc_info("node %s priority=%d role=%s interface=%s (DHCP MAC %s; shared conf %s sha256=%s)",
              ctx->conf.self, ctx->conf.priority,
              ctx->role == HADC_ROLE_MASTER ? "MASTER" : "SLAVE", ctx->conf.interface, macstr,
              ctx->conf.base_path, ctx->conf.sha256);


    ctx->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->epfd < 0) {
        hadc_err("epoll_create1: %s", strerror(errno));
        return 1;
    }

    if (pthread_mutex_init(&ctx->hb_lock, NULL) != 0) {
        hadc_err("pthread_mutex_init: %s", strerror(errno));
        return 1;
    }
    if (ctx->conf.n_members != 0 && pipe2(ctx->hb_selfpipe, O_NONBLOCK | O_CLOEXEC) != 0) {
        hadc_err("pipe2: %s", strerror(errno));
        return 1;
    }

    /* A ctl client can read its reply and close before we are done writing it;
     * the follow-up write then returns EPIPE and the default SIGPIPE disposition
     * would kill the daemon. Ignore it (the writes below already report errors). */
    signal(SIGPIPE, SIG_IGN);

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    hadc_loop_add(ctx, sfd, signal_ready, 0);

    if (hadc_ctl_init(ctx) != 0)
        return 1;
    hadc_cluster_set_role_hook(cb_role_change, ctx);
    if (hadc_cluster_init(ctx) != 0)
        return 1;
    hadc_cluster_timesync(ctx); /* sync CLOCK_REALTIME with the cluster first */
    hadc_cluster_startup_gate(ctx); /* never a second master: a live, higher-ranked
                                     * master seen during the window is followed */
    if (hadc_executor_init(ctx) != 0)
        return 1; /* before election: the role hook brings the link up */
    hadc_executor_monitor_start(ctx); /* drift self-heal: re-apply when managed
                                       * resources change underneath us */
    hadc_routing_init(ctx);
    if (hadc_maint_start(ctx) != 0)
        return 1;
    hadc_ospf_spawn(ctx); /* OSPF RX + tick/FSM/SPF run on their own thread */
    hadc_validate_demote_route_config(ctx, "startup");
    hadc_cluster_elect_check(ctx); /* single-node default role acts at once */
    if (hadc_conntrack_init(ctx) == 0)
        (void)hadc_conntrack_start(ctx);

    /* Startup desired-state pass from the restored cache: apply the interface
     * before the DHCP engine starts (idempotent, hooks fire only on delta). A
     * node that resumes on a persisted lease starts in retention (plan §5): the
     * config is held, nothing is sent, and the engine acts only when a timer is
     * due (renewal unicast to the pinned server-id). */
    {
        hadc_desired_t desired;
        bool resume = pv.found && ctx->lease.address.s_addr != 0;
        hadc_routing_reconcile(ctx, "startup");
        hadc_executor_desired(ctx, &ctx->lease, &desired);
        if (resume && ctx->conf.dhcp.retention != HADC_RETENTION_OFF)
            cb_retention(ctx, true);
        else
            hadc_executor_apply(ctx, &desired, HADC_REASON_REBOOT);
        ctx->acked_version = ctx->lease.version;
    }
    if (ctx->role == HADC_ROLE_MASTER) {
        hadc_executor_announce_cluster(ctx);
        hadc_gwping_start(ctx);
    }
    hadc_conntrack_notify_role(ctx, HADC_ROLE_UNKNOWN, ctx->role);

    static const hadc_dhcp_callbacks_t cb = { cb_lease_update, cb_retention,
                                              cb_carrier_return };
    if (hadc_dhcpcore_init(ctx, &cb, ctx) != 0)
        return 1;
    hadc_dhcpcore_start(ctx); /* master-only; no-op on slaves */

    ctx->maintfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    {
        uint32_t maint_ms = hadc_cluster_maint_interval_ms(ctx);
        struct itimerspec its = {
            .it_interval = { .tv_sec = maint_ms / 1000,
                             .tv_nsec = (long)(maint_ms % 1000) * 1000000 },
            .it_value = { .tv_sec = maint_ms / 1000,
                          .tv_nsec = (long)(maint_ms % 1000) * 1000000 },
        };
        timerfd_settime(ctx->maintfd, 0, &its, NULL);
    }
    hadc_loop_add(ctx, ctx->maintfd, heartbeat_ready, 0);

    ctx->periodicfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    struct itimerspec pits = {
        .it_interval = { .tv_sec = 1, .tv_nsec = 0 },
        .it_value = { .tv_sec = 1, .tv_nsec = 0 },
    };
    timerfd_settime(ctx->periodicfd, 0, &pits, NULL);
    hadc_loop_add(ctx, ctx->periodicfd, periodic_ready, 0);

    if (oneshot) {
        char *status = hadc_ctl_status_json(ctx);
        if (status) {
            printf("%s\n", status);
            free(status);
        }
        hadc_persist_save(ctx);
        return 0;
    }

    ctx->running = true;
    hadc_info("ha-dhcpc %s (built %s)", HADC_VERSION, HADC_BUILD_TIME);
    {
        uint32_t t1, t2, t3;
        hadc_lease_remaining(&ctx->lease, (long long)time(NULL), &t1, &t2, &t3);
        hadc_info("startup: role=%s lease state=%s renew_in=%us rebind_in=%us expire_in=%us",
                  ctx->role == HADC_ROLE_MASTER ? "master" : "slave",
                  hadc_lease_state_name(ctx->lease.state), t1, t2, t3);
    }
    if (ctx->conf.n_members == 0)
        hadc_info("running standalone (no cluster members; heartbeat transport disabled, role master)");
    else
        hadc_info("running (heartbeat %ums, cluster port %u; roles are automatic "
                  "(priority %d), ctl promote/demote still override)",
                  ctx->conf.cluster.heartbeat_ms, (unsigned)ctx->conf.cluster.port,
                  ctx->conf.priority);
    if (ctx->conf.n_members != 0) {
        hadc_loop_add(ctx, ctx->hb_selfpipe[0], hb_selfpipe_ready, 0);
        if (hadc_cluster_hb_start(ctx) != 0)
            hadc_err("heartbeat thread: pthread_create failed (watchdog disabled)");
    }

    struct epoll_event evs[MAX_FDS];
    while (ctx->running) {
        int n = epoll_wait(ctx->epfd, evs, MAX_FDS, 1000);
        for (int i = 0; i < n; i++) {
            int fd = evs[i].data.fd;
            fd_entry_t *e = NULL;
            for (size_t j = 0; j < g_nfds; j++)
                if (g_fds[j].fd == fd) {
                    e = &g_fds[j];
                    break;
                }
            if (evs[i].events & (EPOLLERR | EPOLLHUP)) {
                hadc_warn("loop: fd %d reports %s%s", fd,
                          (evs[i].events & EPOLLERR) ? "EPOLLERR" : "",
                          (evs[i].events & EPOLLHUP)
                              ? ((evs[i].events & EPOLLERR) ? "|EPOLLHUP" : "EPOLLHUP")
                              : "");
                /* A permanently erroring fd makes epoll_wait return
                 * immediately on every pass, pegging a CPU core (an AF_PACKET
                 * socket whose interface was removed). Owners that cannot
                 * re-establish an errored fd mark it HADC_FD_ERR_DROP so we
                 * clean up and deregister it; other subsystems keep their
                 * registration and still get the event delivered. */
                if (e != NULL && (e->flags & HADC_FD_ERR_DROP)) {
                    if (e->cb)
                        e->cb(ctx, fd);
                    hadc_loop_del(ctx, fd);
                    continue;
                }
            }
            if (e != NULL && e->cb)
                e->cb(ctx, fd);
        }
        hadc_cluster_step(ctx);
        hadc_ctl_step(ctx);
        hadc_dhcpcore_step(ctx);
    }
    hadc_conntrack_shutdown(ctx);
    hadc_dhcpcore_stop(ctx);
    hadc_maint_stop(); /* drain pending maintenance/fsync before final cleanup */
    hadc_gwping_stop(ctx);
    hadc_persist_save(ctx); /* while the OSPF LSDB is still alive: captures the
                             * self LSAs the next start restores during its grace */
    hadc_routing_shutdown(ctx);
    if (hadc_cluster_graceful_active(ctx))
        hadc_info("graceful restart active: leaving cluster/VIP state applied on exit");
    else
        hadc_executor_clear_slave_isolation(ctx->conf.interface);
    return 0;
}
