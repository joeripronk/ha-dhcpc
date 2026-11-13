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

#define MAX_FDS 16

typedef struct {
    int fd;
    hadc_fd_cb_t cb;
    int flags;
} fd_entry_t;

static fd_entry_t g_fds[MAX_FDS];
static size_t g_nfds;
static hadc_ctx_t g_ctx;

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

static void periodic_ready(hadc_ctx_t *ctx, int fd)
{
    uint64_t exp;
    (void)!read(fd, &exp, sizeof(exp));
    hadc_executor_audit_tick(ctx); /* rate-limited live-state audit (plan §3) */
    hadc_gwping_tick(ctx); /* 1 s gateway probes + reply timeouts/failover */
    hadc_routing_reconcile(ctx, "periodic");
}

static void signal_ready(hadc_ctx_t *ctx, int fd)
{
    struct signalfd_siginfo si;
    (void)!read(fd, &si, sizeof(si));
    if (ctx->role == HADC_ROLE_MASTER) {
        hadc_lease_t rl = ctx->lease;
        if (rl.observed_at_utc != 0)
            hadc_lease_adjust_elapsed(&rl, (long long)time(NULL) - rl.observed_at_utc);
        hadc_info("shutdown: role=master lease state=%s renew_in=%us rebind_in=%us expire_in=%us",
                  hadc_lease_state_name(rl.state),
                  rl.t1_remaining_s, rl.t2_remaining_s, rl.t3_remaining_s);
    }
    /* Graceful exit: a master hands the role to the best live peer so the
     * cluster elects a new master immediately. With no live peer (or not the
     * master) it just shuts down and leaves service intact — a lone/partitioned
     * master must not withdraw the VIP. During graceful cluster restart the
     * master must not hand off and service (VIP/lease config) is left applied. */
    if (hadc_cluster_graceful_active(ctx)) {
        hadc_info("signal %u received; graceful restart active, shutting down "
                  "without handoff/teardown", si.ssi_signo);
    } else if (ctx->role == HADC_ROLE_MASTER && hadc_cluster_handoff(ctx)) {
        hadc_info("signal %u received; handed off before shutdown", si.ssi_signo);
    } else {
        if (ctx->conf.n_members == 0)
            hadc_info("signal %u received; standalone shutdown, leaving service intact", si.ssi_signo);
        else
            hadc_info("signal %u received; shutting down", si.ssi_signo);
    }
    ctx->shutting_down = true;
    ctx->running = false;
}

/* DHCP engine callbacks (dhcpcore adapter -> daemon). */

static void cb_retention(void *arg, bool entered);

/* Master-side gateway MAC cache (plan §4 sync unit): learn the gateway's
 * lladdr from our own resolved neighbor entry so a promoted node does not
 * have to re-discover it with ARP. 1 = newly cached. */
static int cache_gw_mac(hadc_ctx_t *ctx)
{
    uint8_t mac[HADC_MAC_LEN];

    if (ctx->role != HADC_ROLE_MASTER || ctx->lease.gateway.s_addr == 0)
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
        hadc_info("lease update v%llu state=%s addr=%s t1=%us t3=%us",
                  (unsigned long long)ctx->lease.version,
                  hadc_lease_state_name(ctx->lease.state),
                  inet_ntoa(*(struct in_addr *)&ctx->lease.address),
                  ctx->lease.t1_remaining_s, ctx->lease.t3_remaining_s);
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
    if (ctx->role == HADC_ROLE_SLAVE) {
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
    if (new_role == HADC_ROLE_MASTER) {
        hadc_executor_link_up(ctx->conf.interface); /* the master must speak DHCP */
        hadc_lease_prepare_for_promotion(&ctx->lease);
        {
            hadc_lease_t rl = ctx->lease;
            if (rl.observed_at_utc != 0)
                hadc_lease_adjust_elapsed(&rl, (long long)time(NULL) - rl.observed_at_utc);
            hadc_info("promotion: lease state=%s renew_in=%us rebind_in=%us expire_in=%us",
                      hadc_lease_state_name(rl.state),
                      rl.t1_remaining_s, rl.t2_remaining_s, rl.t3_remaining_s);
        }
    } else {
        if (old_role == HADC_ROLE_MASTER)
            hadc_dhcpcore_stop(ctx);
        if (new_role == HADC_ROLE_SLAVE) {
            hadc_lease_t rl = ctx->lease;
            if (rl.observed_at_utc != 0)
                hadc_lease_adjust_elapsed(&rl, (long long)time(NULL) - rl.observed_at_utc);
            hadc_info("demotion: lease state=%s renew_in=%us rebind_in=%us expire_in=%us",
                      hadc_lease_state_name(rl.state),
                      rl.t1_remaining_s, rl.t2_remaining_s, rl.t3_remaining_s);
        }
    }
    hadc_routing_reconcile(ctx, new_role == HADC_ROLE_MASTER ? "promote" : "demote");
    hadc_executor_desired(ctx, &ctx->lease, &desired);
    hadc_executor_apply(ctx, &desired, new_role == HADC_ROLE_MASTER ? "PROMOTE" : "DEMOTE");
    if (new_role == HADC_ROLE_MASTER) {
        hadc_dhcpcore_start(ctx); /* resume after the dataplane (pin/neigh/route) is applied */
        hadc_executor_announce_cluster(ctx);
        hadc_gwping_start(ctx); /* verify the gateway after a promote */
    } else if (old_role == HADC_ROLE_MASTER)
        hadc_gwping_stop(ctx);
    ctx->acked_version = ctx->lease.version;
    hadc_persist_save(ctx);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [--conf PATH] [--local-conf PATH] [--persist PATH] [--oneshot]\n"
            "       %s [--conf PATH] [--local-conf PATH] ctl promote|demote|status|update|renew|newip [id]\n"
            "       %s [--conf PATH] [--local-conf PATH] ctl graceful-restart enable|disable\n"
            "       (--persist default: state.json next to --conf)\n",
            argv0, argv0, argv0);
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

int main(int argc, char **argv)
{
    const char *conf_path = "/etc/ha-dhcpc/ha-dhcpc.conf";
    const char *local_path = "/etc/ha-dhcpc/ha-dhcpc-local.conf";
    const char *persist_path = NULL; /* default: state.json next to the config */
    bool oneshot = false;
    hadc_ctx_t *ctx = &g_ctx;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--conf") && i + 1 < argc) {
            conf_path = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "--local-conf") && i + 1 < argc) {
            local_path = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "ctl") && i + 1 < argc) {
            char cmd[256] = "";
            for (int j = i + 1; j < argc; j++) {
                if (cmd[0])
                    strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
                strncat(cmd, argv[j], sizeof(cmd) - strlen(cmd) - 1);
            }
            return ctl_client(conf_path, local_path, cmd);
        }
    }

    for (int i = 1; i < argc; i++) {
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
        char a[64], nm[64], gw[64];
        inet_ntop(AF_INET, &ctx->lease.address, a, sizeof(a));
        inet_ntop(AF_INET, &ctx->lease.netmask, nm, sizeof(nm));
        inet_ntop(AF_INET, &ctx->lease.gateway, gw, sizeof(gw));
        hadc_info("persist: restored role=%s lease_version=%llu state=%s addr=%s "
                  "mask=%s gateway=%s dns=%zu t1=%us t2=%us t3=%us acked=%llu",
                  ctx->role == HADC_ROLE_MASTER ? "master" : "slave",
                  (unsigned long long)pv.lease_version, hadc_lease_state_name(ctx->lease.state),
                  a, nm, gw, ctx->lease.n_dns, ctx->lease.t1_remaining_s,
                  ctx->lease.t2_remaining_s, ctx->lease.t3_remaining_s,
                  (unsigned long long)ctx->acked_version);
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
    hadc_ospf_spawn(ctx); /* OSPF RX + tick/FSM/SPF run on their own thread */
    hadc_cluster_elect_check(ctx); /* single-node default role acts at once */

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

    static const hadc_dhcp_callbacks_t cb = { cb_lease_update, cb_retention,
                                              cb_carrier_return };
    if (hadc_dhcpcore_init(ctx, &cb, ctx) != 0)
        return 1;
    hadc_dhcpcore_start(ctx); /* master-only; no-op on slaves */

    ctx->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    struct itimerspec its = {
        .it_interval = { .tv_sec = ctx->conf.cluster.heartbeat_ms / 1000,
                         .tv_nsec = (long)(ctx->conf.cluster.heartbeat_ms % 1000) * 1000000 },
        .it_value = { .tv_sec = ctx->conf.cluster.heartbeat_ms / 1000,
                      .tv_nsec = (long)(ctx->conf.cluster.heartbeat_ms % 1000) * 1000000 },
    };
    timerfd_settime(ctx->timerfd, 0, &its, NULL);
    hadc_loop_add(ctx, ctx->timerfd, heartbeat_ready, 0);

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
    {
        hadc_lease_t rl = ctx->lease;
        if (rl.observed_at_utc != 0)
            hadc_lease_adjust_elapsed(&rl, (long long)time(NULL) - rl.observed_at_utc);
        hadc_info("startup: role=%s lease state=%s renew_in=%us rebind_in=%us expire_in=%us",
                  ctx->role == HADC_ROLE_MASTER ? "master" : "slave",
                  hadc_lease_state_name(rl.state),
                  rl.t1_remaining_s, rl.t2_remaining_s, rl.t3_remaining_s);
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
    hadc_dhcpcore_stop(ctx);
    hadc_gwping_stop(ctx);
    hadc_routing_shutdown(ctx);
    if (hadc_cluster_graceful_active(ctx))
        hadc_info("graceful restart active: leaving cluster/VIP state applied on exit");
    else
        hadc_executor_clear_slave_isolation(ctx->conf.interface);
    hadc_persist_save(ctx);
    return 0;
}
