/* ha-dhcpc daemon — M1 scaffold (plan §10).
 * Loads the three config files, restores the persisted cluster view,
 * runs one epoll event loop (heartbeat timer + ctl socket + UDP transport).
 * DHCP engine, cluster decisions and netlink application are stubs wired
 * through the frozen M0 interfaces. */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
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
#include "internal.h"

#include <sys/socket.h>
#include <sys/un.h>

#define MAX_FDS 16

typedef struct {
    int fd;
    hadc_fd_cb_t cb;
} fd_entry_t;

static fd_entry_t g_fds[MAX_FDS];
static size_t g_nfds;
static hadc_ctx_t g_ctx;

int hadc_loop_add(hadc_ctx_t *ctx, int fd, hadc_fd_cb_t cb, int events)
{
    (void)events;
    if (g_nfds >= MAX_FDS || fd < 0)
        return -1;
    g_fds[g_nfds].fd = fd;
    g_fds[g_nfds].cb = cb;
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
        hadc_err("loop: epoll del fd %d: %s", fd, strerror(errno));
        return -1;
    }
    return 0;
}

static void heartbeat_fire(hadc_ctx_t *ctx)
{
    hadc_cluster_heartbeat(ctx); /* bidirectional, with lease summary (plan §4) */
}

static void timer_ready(hadc_ctx_t *ctx, int fd)
{
    uint64_t exp;
    (void)!read(fd, &exp, sizeof(exp));
    heartbeat_fire(ctx);
}

static void signal_ready(hadc_ctx_t *ctx, int fd)
{
    struct signalfd_siginfo si;
    (void)!read(fd, &si, sizeof(si));
    hadc_info("signal %u received; shutting down", si.ssi_signo);
    ctx->running = false;
}

/* DHCP engine callbacks (dhcpcore adapter -> daemon). */

static void cb_lease_update(void *arg, const hadc_lease_t *lease)
{
    hadc_ctx_t *ctx = arg;
    hadc_desired_t desired;

    if (lease != NULL) {
        bool retention = ctx->lease.retention_active;
        ctx->lease = *lease;
        ctx->lease.retention_active = retention;
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
    } else {
        hadc_warn("lease gone (EXPIRE/FAIL); no desired state");
        memset(&ctx->lease, 0, sizeof(ctx->lease));
        hadc_executor_desired(ctx, &ctx->lease, &desired);
        hadc_executor_apply(ctx, &desired, HADC_REASON_EXPIRE);
    }
    ctx->acked_version = ctx->lease.version;
    hadc_cluster_push_state(ctx, &ctx->lease); /* master-only (plan §4) */
    hadc_persist_save(ctx);
}

static void cb_retention(void *arg, bool entered)
{
    hadc_ctx_t *ctx = arg;
    hadc_desired_t desired;

    hadc_info("retention %s (plan §5)", entered ? "enter" : "exit");
    ctx->lease.retention_active = entered;
    if (entered)
        ctx->lease.state = HADC_LEASE_RETAINED;
    else if (ctx->lease.state == HADC_LEASE_RETAINED)
        ctx->lease.state = HADC_LEASE_BOUND;
    hadc_executor_desired(ctx, &ctx->lease, &desired);
    hadc_executor_apply(ctx, &desired, entered ? "RETAINED-ENTER" : "RETAINED-EXIT");
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

/* Role transitions (ctl/keepalived/cluster-driven, plan §4): the engine runs
 * only on the master; a promoted node resumes renew-only on the synced lease. */
static void cb_role_change(void *arg, hadc_role_t old_role, hadc_role_t new_role)
{
    hadc_ctx_t *ctx = arg;
    hadc_desired_t desired;

    if (old_role == new_role)
        return;
    if (new_role == HADC_ROLE_MASTER)
        hadc_dhcpcore_start(ctx);
    else if (old_role == HADC_ROLE_MASTER)
        hadc_dhcpcore_stop(ctx);
    hadc_executor_desired(ctx, &ctx->lease, &desired);
    hadc_executor_apply(ctx, &desired, new_role == HADC_ROLE_MASTER ? "PROMOTE" : "DEMOTE");
    ctx->acked_version = ctx->lease.version;
    hadc_persist_save(ctx);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [--master-conf PATH] [--slave-conf PATH] [--conf PATH]\n"
            "       %s [--persist PATH] [--oneshot]\n"
            "       %s [--conf PATH] ctl promote|demote|status [id]\n",
            argv0, argv0, argv0);
}

/* Client mode: ha-dhcpc [conf path] ctl promote|demote|status [id] (plan §3). */
static int ctl_client(const char *conf_path, const char *cmd_line)
{
    hadc_daemon_conf_t conf;
    char err[256];
    char line[256];
    char reply[4096];

    if (hadc_config_load_daemon(conf_path, &conf, err, sizeof(err)) != 0) {
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
    const char *master_path = "/etc/ha-dhcpc/master.conf";
    const char *slave_path = "/etc/ha-dhcpc/slave.conf";
    const char *conf_path = "/etc/ha-dhcpc/ha-dhcpc.yaml";
    const char *persist_path = "/var/lib/ha-dhcpc/state.json";
    bool oneshot = false;
    hadc_ctx_t *ctx = &g_ctx;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--conf") && i + 1 < argc) {
            conf_path = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "ctl") && i + 1 < argc) {
            char cmd[256] = "";
            for (int j = i + 1; j < argc; j++) {
                if (cmd[0])
                    strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
                strncat(cmd, argv[j], sizeof(cmd) - strlen(cmd) - 1);
            }
            return ctl_client(conf_path, cmd);
        }
    }

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--master-conf") && i + 1 < argc)
            master_path = argv[++i];
        else if (!strcmp(argv[i], "--slave-conf") && i + 1 < argc)
            slave_path = argv[++i];
        else if (!strcmp(argv[i], "--conf") && i + 1 < argc)
            conf_path = argv[++i];
        else if (!strcmp(argv[i], "--persist") && i + 1 < argc)
            persist_path = argv[++i];
        else if (!strcmp(argv[i], "--oneshot"))
            oneshot = true;
        else {
            usage(argv[0]);
            return 2;
        }
    }

    char err[512];
    if (hadc_config_load_master(master_path, &ctx->master, err, sizeof(err)) ||
        hadc_config_load_slave(slave_path, &ctx->slave, err, sizeof(err)) ||
        hadc_config_load_daemon(conf_path, &ctx->conf, err, sizeof(err))) {
        hadc_err("config: %s", err);
        return 1;
    }

    /* Initial role: obey persisted view, else the designated master in master.conf. */
    hadc_persist_init(ctx, persist_path);
    hadc_persist_view_t pv;
    hadc_persist_load(ctx, &pv);
    ctx->role = pv.found ? pv.role : (!strcmp(ctx->master.designated_master, ctx->slave.self)
                                          ? HADC_ROLE_MASTER
                                          : HADC_ROLE_SLAVE);
    if (pv.found) {
        ctx->lease = pv.lease;
        ctx->lease.version = pv.lease_version;
        ctx->acked_version = pv.acked_version;
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

    const char *self_mac_src = "master.conf";
    char macstr[32];
    snprintf(macstr, sizeof(macstr), "%02x:%02x:%02x:%02x:%02x:%02x", ctx->master.master_mac[0],
             ctx->master.master_mac[1], ctx->master.master_mac[2], ctx->master.master_mac[3],
             ctx->master.master_mac[4], ctx->master.master_mac[5]);
    hadc_info("node %s priority=%d role=%s interface=%s (DHCP MAC %s copied from %s)",
              ctx->slave.self, ctx->slave.priority,
              ctx->role == HADC_ROLE_MASTER ? "MASTER" : "SLAVE", ctx->conf.interface, macstr,
              self_mac_src);

    ctx->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (ctx->epfd < 0) {
        hadc_err("epoll_create1: %s", strerror(errno));
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
    hadc_cluster_elect_check(ctx); /* single-node default role acts at once */
    if (hadc_executor_init(ctx) != 0)
        return 1;

    /* Startup desired-state pass from the restored cache: apply the interface
     * before the DHCP engine starts (idempotent, hooks fire only on delta). */
    {
        hadc_desired_t desired;
        hadc_executor_desired(ctx, &ctx->lease, &desired);
        hadc_executor_apply(ctx, &desired, HADC_REASON_REBOOT);
        ctx->acked_version = ctx->lease.version;
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
    hadc_loop_add(ctx, ctx->timerfd, timer_ready, 0);

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
    hadc_info("running (heartbeat %ums, cluster port %u; keepalived drives roles via ctl)",
              ctx->conf.cluster.heartbeat_ms, (unsigned)ctx->conf.cluster.port);
    struct epoll_event evs[MAX_FDS];
    while (ctx->running) {
        int n = epoll_wait(ctx->epfd, evs, MAX_FDS, 1000);
        for (int i = 0; i < n; i++) {
            for (size_t j = 0; j < g_nfds; j++)
                if (g_fds[j].fd == evs[i].data.fd && g_fds[j].cb)
                    g_fds[j].cb(ctx, g_fds[j].fd);
        }
        hadc_cluster_step(ctx);
        hadc_ctl_step(ctx);
        hadc_dhcpcore_step(ctx);
    }
    hadc_dhcpcore_stop(ctx);
    hadc_persist_save(ctx);
    return 0;
}
