/* Control interface: unix socket, plaintext commands, JSON replies (plan §3/§4).
 * Idempotent, logged, auditable. */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/conntrack.h"
#include "ha-dhcpc/ctl.h"
#include "ha-dhcpc/dhcpcore.h"
#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/ipv4.h"
#include "ha-dhcpc/lease.h"
#include "ha-dhcpc/log.h"
#include "ha-dhcpc/reload.h"
#include "ha-dhcpc/routing.h"
#include "internal.h"

static char g_ctl_path[HADC_PATH_MAX]; /* where ctl_fd is bound (rebind check) */

/* A conntrack compare is driven by the conntrack worker; polling for its
 * result must not block the epoll loop. The accepted fd stays open and the
 * final single-line reply is written from hadc_ctl_step(). */
#define CTL_PENDING_MAX 8
#define CTL_COMPARE_TIMEOUT_MS 10000

typedef struct {
    int fd;
    long long deadline_ms;
    char *reply;
    size_t off;
} ctl_pending_t;

static ctl_pending_t g_pending[CTL_PENDING_MAX];
static long long g_ctl_retry_at_ms; /* broken listener recreation deadline */

static json_t *status_object(hadc_ctx_t *ctx)
{
    bool gr_active = hadc_cluster_graceful_active(ctx);
    json_t *o = json_pack(
        "{s:s, s:s, s:s, s:I, s:b, s:s, s:o}", "role", hadc_role_name(ctx->role), "self",
        ctx->conf.self, "master", ctx->conf.designated_master, "lease_version",
        (json_int_t)ctx->lease.version, "retention", (int)ctx->lease.retention_active,
        "conf_sha256", ctx->conf.sha256, "timers",
        json_pack("{s:I, s:I}", "heartbeat_ms", (json_int_t)ctx->conf.cluster.heartbeat_ms,
                  "election_deadline_ms", (json_int_t)ctx->conf.cluster.election_deadline_ms));
    if (!o)
        return NULL;
    json_t *members = json_array();
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        char addr[INET_ADDRSTRLEN];
        hadc_ipv4_format(ctx->conf.members[i].sync_address, addr, sizeof(addr));
        json_array_append_new(
            members,
            json_pack("{s:s, s:s, s:b, s:I, s:s, s:s, s:s}", "id", ctx->conf.members[i].id,
                      "sync_address", addr, "alive", ctx->peers[i].alive, "acked_version",
                      (json_int_t)ctx->peers[i].acked_version, "conf_sha256",
                      ctx->peers[i].conf_sha256, "role",
                      ctx->peers[i].role_view[0] ? ctx->peers[i].role_view : "unknown",
                      "master_view", ctx->peers[i].master_view));
    }
    json_object_set_new(o, "graceful_restart",
        json_pack("{s:b, s:I}", "active", gr_active, "until_ms",
                  (json_int_t)ctx->graceful_restart_until_ms));
    json_object_set_new(o, "demote_route_via_new_master",
        json_pack("{s:b, s:b, s:b, s:s}",
                  "configured", ctx->conf.apply.demote_route_via_new_master,
                  "active", ctx->demote_route_via_new_master_active,
                  "invalid", ctx->demote_route_via_new_master_invalid,
                  "reason", ctx->demote_route_via_new_master_reason));
    json_object_set_new(o, "members", members);
    {
        hadc_lease_t rl = ctx->lease;
        uint32_t t1, t2, t3;
        hadc_lease_remaining(&rl, (long long)time(NULL), &t1, &t2, &t3);
        char la[64], ln[64], lg[64], ls[64];
        hadc_ipv4_format(rl.address, la, sizeof(la));
        hadc_ipv4_format(rl.netmask, ln, sizeof(ln));
        hadc_ipv4_format(rl.gateway, lg, sizeof(lg));
        hadc_ipv4_format(rl.server_id, ls, sizeof(ls));
        json_t *dns = json_array();
        for (size_t i = 0; i < rl.n_dns; i++) {
            char b[64];
            hadc_ipv4_format(rl.dns[i], b, sizeof(b));
            json_array_append_new(dns, json_string(b));
        }
        json_object_set_new(o, "dhcp",
            json_pack("{s:s, s:s, s:s, s:s, s:s, s:o, s:I, s:I, s:I, s:I, s:I, s:I, s:I}",
                      "state", hadc_lease_state_name(rl.state),
                      "address", la, "netmask", ln, "gateway", lg, "server_id", ls,
                      "dns", dns, "t1_remaining_s", (json_int_t)t1,
                      "t2_remaining_s", (json_int_t)t2,
                      "t3_remaining_s", (json_int_t)t3,
                      "obtained_at_utc", (json_int_t)rl.obtained_at_utc,
                      "t1_at_utc", (json_int_t)rl.t1_at_utc,
                      "t2_at_utc", (json_int_t)rl.t2_at_utc,
                      "t3_at_utc", (json_int_t)rl.t3_at_utc));
        json_object_set_new(o, "gwping",
            json_pack("{s:b, s:b}", "enabled", ctx->conf.apply.gateway_probe,
                      "unreachable", hadc_gwping_unreachable()));
    }
    json_t *cluster = json_array();
    for (size_t i = 0; i < ctx->conf.cluster.n_ifaces; i++) {
        const hadc_cluster_if_t *ci = &ctx->conf.cluster.ifaces[i];
        json_t *addrs = json_array();
        for (size_t j = 0; j < ci->n_addrs; j++) {
            char buf[64];
            char ib[INET_ADDRSTRLEN]; hadc_ipv4_format(ci->addrs[j].address, ib, sizeof(ib)); snprintf(buf, sizeof(buf), "%s/%u", ib,
                     ci->addrs[j].prefixlen);
            json_array_append_new(addrs, json_string(buf));
        }
        json_array_append_new(cluster,
            json_pack("{s:s, s:b, s:o}", "interface", ci->interface, "owned",
                      ((ctx->role == HADC_ROLE_MASTER || ctx->role == HADC_ROLE_PROMOTING) || ctx->role == HADC_ROLE_PROMOTING), "addresses", addrs));
    }
    json_object_set_new(o, "cluster_addresses", cluster);
    json_object_set_new(o, "executor", hadc_executor_status());
    json_object_set_new(o, "routing", hadc_routing_status(ctx));
    {
        char *ct = hadc_conntrack_status_json(ctx);
        if (ct) {
            json_error_t jerr;
            json_t *j = json_loads(ct, 0, &jerr);
            if (j)
                json_object_set_new(o, "conntrack_sync", j);
            free(ct);
        }
    }
    return o;
}

char *hadc_ctl_status_json(hadc_ctx_t *ctx)
{
    json_t *o = status_object(ctx);
    char *txt = json_dumps(o, JSON_PRESERVE_ORDER | JSON_COMPACT);
    json_decref(o);
    return txt;
}

/* Reserve a deferred reply slot; fd >= 0 is owned by the slot until the reply
 * is written. Returns 0 when no slot is free. */
static int ctl_pending_add(int fd, long long deadline_ms)
{
    for (size_t i = 0; i < CTL_PENDING_MAX; i++) {
        if (g_pending[i].fd < 0) {
            g_pending[i].fd = fd;
            g_pending[i].deadline_ms = deadline_ms;
            g_pending[i].reply = NULL;
            g_pending[i].off = 0;
            return 0;
        }
    }
    return -1;
}

static void handle_command(hadc_ctx_t *ctx, const char *line, int reply_fd, int *deferred)
{
    char cmd[64] = "", arg[128] = "";
    if (sscanf(line, "%63s %127s", cmd, arg) < 1)
        return;
    const char *reply = "{\"ok\":true}";
    if (!strcmp(cmd, "promote")) {
        const char *target = arg[0] ? arg : ctx->conf.self;
        hadc_info("ctl: promote %s", target);
        if (ctx->role != HADC_ROLE_MASTER &&
            ctx->conf.designated_master[0] &&
            strcmp(ctx->conf.designated_master, ctx->conf.self) != 0) {
            const hadc_member_t *master = NULL;
            for (size_t i = 0; i < ctx->conf.n_members; i++)
                if (!strcmp(ctx->conf.members[i].id, ctx->conf.designated_master))
                    master = &ctx->conf.members[i];
            if (master && ctx->udp_fd >= 0) {
                json_t *msg = json_pack("{s:s, s:s, s:s, s:I, s:s}", "type", HADC_MSG_CTL_PROMOTE,
                                        "origin", ctx->conf.self, "master_id",
                                        ctx->conf.designated_master, "lease_version",
                                        (json_int_t)ctx->lease.version, "new_master", target);
                bool forwarded = false;
                if (msg) {
                    char *txt = json_dumps(msg, JSON_PRESERVE_ORDER | JSON_COMPACT);
                    if (txt) {
                        struct sockaddr_in to = { .sin_family = AF_INET,
                                                  .sin_port = htons(ctx->conf.cluster.port),
                                                  .sin_addr = master->sync_address };
                        ssize_t n = sendto(ctx->udp_fd, txt, strlen(txt), 0,
                                           (struct sockaddr *)&to, sizeof(to));
                        forwarded = n >= 0;
                        if (!forwarded)
                            hadc_warn("ctl: promote forward to master %s failed: %s",
                                      ctx->conf.designated_master, strerror(errno));
                        free(txt);
                    }
                    json_decref(msg);
                }
                if (forwarded) {
                    hadc_info("ctl: promote request for %s forwarded to master %s", target,
                              ctx->conf.designated_master);
                    reply = "{\"ok\":true,\"forwarded\":true}";
                } else {
                    hadc_warn("ctl: promote request for %s could not be forwarded to master %s",
                              target, ctx->conf.designated_master);
                    reply = "{\"ok\":false,\"forwarded\":false,\"error\":\"forward failed\"}";
                }
            } else {
                hadc_warn("ctl: promote cannot forward to master %s; attempting locally",
                          ctx->conf.designated_master);
                if (hadc_cluster_promote(ctx, target) != 0)
                    reply = "{\"ok\":false,\"error\":\"promote failed\"}";
            }
        } else {
            if (hadc_cluster_promote(ctx, target) != 0)
                reply = "{\"ok\":false,\"error\":\"promote failed\"}";
        }
    } else if (!strcmp(cmd, "demote")) {
        hadc_info("ctl: demote");
        hadc_cluster_demote(ctx);
    } else if (!strcmp(cmd, "status")) {
        char *txt = hadc_ctl_status_json(ctx);
        if (txt) {
            char nl = '\n';
            (void)!write(reply_fd, txt, strlen(txt));
            (void)!write(reply_fd, &nl, 1);
            free(txt);
            reply = NULL;
        }
    } else if (!strcmp(cmd, "update")) {
        /* The master's copy of the shared document is authoritative (plan §6):
         * re-read it from disk, apply it here, then publish it to every member. */
        if (ctx->role != HADC_ROLE_MASTER) {
            hadc_warn("ctl: update refused here (role %s); only the master publishes",
                      hadc_role_name(ctx->role));
            reply = "{\"ok\":false,\"error\":\"not master\"}";
        } else if (hadc_conf_reload(ctx, "ctl_update") != 0) {
            reply = "{\"ok\":false,\"error\":\"reload failed; config in use unchanged\"}";
        } else {
            char out[192], nl = '\n';
            snprintf(out, sizeof(out), "{\"ok\":true,\"conf_sha256\":\"%s\"}", ctx->conf.sha256);
            (void)!write(reply_fd, out, strlen(out));
            (void)!write(reply_fd, &nl, 1);
            reply = NULL;
            hadc_cluster_push_conf(ctx, NULL);
        }
    } else if (!strcmp(cmd, "renew")) {
        if (ctx->role != HADC_ROLE_MASTER) {
            hadc_warn("ctl: renew refused here (role %s); only the master speaks DHCP",
                      hadc_role_name(ctx->role));
            reply = "{\"ok\":false,\"error\":\"not master\"}";
        } else if (hadc_dhcpcore_force_renew(ctx) != 0) {
            /* Stale lease: nothing to renew — fall back to a fresh lease
             * (plan §5: RENEW → REBIND → fresh DISCOVER). */
            if (hadc_dhcpcore_force_discover(ctx) != 0)
                reply = "{\"ok\":false,\"error\":\"renew failed\"}";
            else
                hadc_info("ctl: no active lease to renew; fell back to a fresh "
                    "DISCOVER");
        } else {
            hadc_info("ctl: renew forced a DHCPREQUEST");
        }
    } else if (!strcmp(cmd, "newip")) {
        if (ctx->role != HADC_ROLE_MASTER) {
            hadc_warn("ctl: newip refused here (role %s); only the master speaks DHCP",
                      hadc_role_name(ctx->role));
            reply = "{\"ok\":false,\"error\":\"not master\"}";
        } else if (hadc_dhcpcore_force_discover(ctx) != 0) {
            reply = "{\"ok\":false,\"error\":\"newip failed\"}";
        } else {
            ctx->newip_old_addr = ctx->lease.address;
            ctx->newip_pending = true;
            {
                char oldbuf[INET_ADDRSTRLEN] = "none";
                if (ctx->newip_old_addr.s_addr)
                    hadc_ipv4_format(ctx->newip_old_addr, oldbuf, sizeof(oldbuf));
                hadc_info("ctl: newip forced a fresh DISCOVER (old=%s, abort_tcp=%s)",
                          oldbuf, ctx->conf.apply.abort_tcp_on_newip ? "on" : "off");
            }
        }
    } else if (!strcmp(cmd, "graceful-restart")) {
        if (ctx->role != HADC_ROLE_MASTER) {
            hadc_warn("ctl: graceful-restart refused here (role %s); only the master sets it",
                      hadc_role_name(ctx->role));
            reply = "{\"ok\":false,\"error\":\"not master\"}";
        } else if (!strcmp(arg, "enable") || !strcmp(arg, "on")) {
            hadc_cluster_set_graceful_restart(ctx, true);
        } else if (!strcmp(arg, "disable") || !strcmp(arg, "off") || !strcmp(arg, "cancel")) {
            hadc_cluster_set_graceful_restart(ctx, false);
        } else {
            reply = "{\"ok\":false,\"error\":\"usage: graceful-restart enable|disable\"}";
        }
    } else if (!strcmp(cmd, "conntrack")) {
        if (!strcmp(arg, "resync")) {
            if (hadc_conntrack_resync(ctx) != 0)
                reply = "{\"ok\":false,\"error\":\"conntrack resync unavailable\"}";
            else
                reply = "{\"ok\":true}";
        } else if (!strcmp(arg, "compare")) {
            if (ctx->role != HADC_ROLE_SLAVE) {
                reply = "{\"ok\":false,\"error\":\"conntrack compare requires slave role\"}";
            } else if (hadc_conntrack_compare(ctx) != 0) {
                reply = "{\"ok\":false,\"error\":\"conntrack compare unavailable\"}";
            } else if (ctl_pending_add(reply_fd, hadc_now_ms() + CTL_COMPARE_TIMEOUT_MS) != 0) {
                reply = "{\"ok\":false,\"error\":\"too many pending compares\"}";
            } else {
                /* The worker finishes asynchronously; hadc_ctl_step writes the
                 * only reply on this fd when the result is ready. */
                *deferred = 1;
                reply = NULL;
            }
        } else {
            reply = "{\"ok\":false,\"error\":\"usage: conntrack resync|compare\"}";
        }
    } else if (!strcmp(cmd, "shutdown") || !strcmp(cmd, "kill") || !strcmp(cmd, "quit") || !strcmp(cmd, "stop")) {
        bool force = !strcmp(cmd, "kill") || !strcmp(arg, "now") || !strcmp(arg, "force");
        hadc_info("ctl: %s%s", cmd, force && strcmp(cmd, "kill") ? " now" : "");
        if (ctx->conf.n_members == 0) {
            hadc_info("ctl shutdown: standalone shutdown, leaving service intact");
            ctx->shutting_down = true;
            ctx->running = false;
        } else if (hadc_cluster_graceful_active(ctx)) {
            hadc_info("ctl shutdown: graceful restart active, shutting down without handoff/teardown");
            ctx->shutting_down = true;
            ctx->running = false;
        } else if ((ctx->role == HADC_ROLE_MASTER || ctx->role == HADC_ROLE_PROMOTING) && hadc_cluster_handoff(ctx)) {
            hadc_info("ctl shutdown: handed off before shutdown");
            ctx->shutting_down = true;
            ctx->running = false;
        } else if (force) {
            hadc_warn("ctl shutdown: no live peer available for handoff; shutting down without handoff");
            ctx->shutting_down = true;
            ctx->running = false;
        } else {
            hadc_warn("ctl shutdown: no live peer available for handoff; shutdown cancelled (use 'shutdown now' or 'kill')");
            reply = "{\"ok\":false,\"error\":\"no live peer for handoff\"}";
        }
    } else {
        hadc_warn("ctl: unknown command '%s'", cmd);
        reply = "{\"ok\":false}";
    }
    if (reply) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%s\n", reply);
        (void)!write(reply_fd, buf, strlen(buf));
    }
}

static void ctl_ready(hadc_ctx_t *ctx, int fd)
{
    /* Linux does not inherit O_NONBLOCK from a nonblocking listener through
     * accept(); without accept4 a client that connects and sends nothing
     * blocks this epoll callback and stalls the whole main loop. */
    int c = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (c < 0) {
        /* Deregister here as well: on a plain EPOLLIN the main loop would not
         * do it, leaving a stale g_fds entry that could match a reused fd.
         * hadc_ctl_step() recreates the listener after a short delay. */
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR &&
            errno != EMFILE && errno != ENFILE) {
            hadc_warn("ctl: listener fd %d unusable: %s", fd, strerror(errno));
            hadc_loop_del(ctx, fd);
            close(fd);
            if (ctx->ctl_fd == fd) {
                ctx->ctl_fd = -1;
                g_ctl_retry_at_ms = hadc_now_ms() + 1000;
            }
        }
        return;
    }
    char line[256];
    size_t used = 0;
    for (;;) {
        ssize_t n = read(c, line + used, sizeof(line) - 1 - used);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break; /* EAGAIN: no more data available without blocking */
        }
        if (n == 0)
            break;
        used += (size_t)n;
        if (memchr(line, '\n', used) || used == sizeof(line) - 1)
            break;
    }
    if (used > 0) {
        line[used] = '\0';
        line[strcspn(line, "\r\n")] = '\0';
        int deferred = 0;
        handle_command(ctx, line, c, &deferred);
        if (deferred)
            return; /* hadc_ctl_step owns fd c until the compare completes */
    }
    close(c);
}

int hadc_ctl_init(hadc_ctx_t *ctx)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%.*s", (int)sizeof(addr.sun_path) - 1,
             ctx->conf.ctl_socket);

    ctx->ctl_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (ctx->ctl_fd < 0) {
        hadc_err("ctl: socket: %s", strerror(errno));
        return -1;
    }
    /* Probe for a live holder without blocking startup indefinitely. */
    int tmp_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (tmp_fd >= 0) {
        int cr = connect(tmp_fd, (struct sockaddr *)&addr, sizeof(addr));
        if (cr == 0) {
            close(tmp_fd);
            close(ctx->ctl_fd);
            ctx->ctl_fd = -1;
            hadc_err("ctl: %s is held by a live ha-dhcpc; refusing to start",
                     ctx->conf.ctl_socket);
            return -1;
        }
        if (errno == EINPROGRESS) {
            struct pollfd pfd = { .fd = tmp_fd, .events = POLLOUT };
            cr = poll(&pfd, 1, 200);
            if (cr > 0) {
                int soerr = 0;
                socklen_t slen = sizeof(soerr);
                getsockopt(tmp_fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
                if (soerr == 0) {
                    close(tmp_fd);
                    close(ctx->ctl_fd);
                    ctx->ctl_fd = -1;
                    hadc_err("ctl: %s is held by a live ha-dhcpc; refusing to start",
                             ctx->conf.ctl_socket);
                    return -1;
                }
            }
            /* timeout or connect error: not a responsive live daemon */
        }
        close(tmp_fd);
        unlink(ctx->conf.ctl_socket); /* stale socket from a dead daemon */
    }
    if (bind(ctx->ctl_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        hadc_err("ctl: bind %s: %s", ctx->conf.ctl_socket, strerror(errno));
        return -1;
    }
    listen(ctx->ctl_fd, 8);
    hadc_loop_add(ctx, ctx->ctl_fd, ctl_ready, HADC_FD_ERR_DROP);
    snprintf(g_ctl_path, sizeof(g_ctl_path), "%s", addr.sun_path);
    hadc_info("ctl: listening on %s", ctx->conf.ctl_socket);
    return 0;
}

/* A path with a socket file may still be stale; only a listening daemon answers
 * a connect. Keep this separate from unlink so a rebind never removes another
 * live instance's control socket. */
static int ctl_path_live(const char *path)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%.*s", (int)sizeof(addr.sun_path) - 1, path);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return 0;
    int live = 0;
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        live = 1;
    } else if (errno == EINPROGRESS) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        if (poll(&pfd, 1, 200) > 0) {
            int soerr = 0;
            socklen_t slen = sizeof(soerr);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0 && soerr == 0)
                live = 1;
        }
    }
    close(fd);
    return live;
}

/* Move the control socket after a reload changed ctl_socket; 0 when unchanged. */
int hadc_ctl_rebind(hadc_ctx_t *ctx)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%.*s", (int)sizeof(addr.sun_path) - 1,
             ctx->conf.ctl_socket);
    if (ctx->ctl_fd >= 0 && strcmp(addr.sun_path, g_ctl_path) == 0)
        return 0;

    /* Bind the new socket before touching the old one: a failed rebind must
     * leave the current control socket working, not strand the operator. */
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        hadc_err("ctl: socket: %s", strerror(errno));
        return -1;
    }
    if (ctl_path_live(addr.sun_path)) {
        hadc_err("ctl: %s is held by a live ha-dhcpc; refusing rebind", ctx->conf.ctl_socket);
        close(fd);
        return -1;
    }
    unlink(addr.sun_path); /* stale file from a dead daemon */
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        hadc_err("ctl: bind %s: %s", ctx->conf.ctl_socket, strerror(errno));
        close(fd);
        return -1;
    }
    listen(fd, 8);
    if (hadc_loop_add(ctx, fd, ctl_ready, HADC_FD_ERR_DROP) != 0) {
        hadc_err("ctl: cannot register new control socket: %s", strerror(errno));
        close(fd);
        unlink(addr.sun_path);
        return -1;
    }
    int old = ctx->ctl_fd;
    ctx->ctl_fd = fd;
    if (old >= 0) {
        hadc_loop_del(ctx, old);
        close(old);
        unlink(g_ctl_path);
    }
    snprintf(g_ctl_path, sizeof(g_ctl_path), "%s", addr.sun_path);
    hadc_info("ctl: control socket moved to %s", g_ctl_path);
    return 1;
}

static void ctl_pending_release(ctl_pending_t *p)
{
    free(p->reply);
    p->reply = NULL;
    p->off = 0;
    close(p->fd);
    p->fd = -1;
}

static char *compare_reply_json(hadc_ctx_t *ctx, bool done)
{
    char *cmp_txt = hadc_conntrack_compare_json(ctx);
    json_t *cmp = NULL;
    if (cmp_txt) {
        json_error_t jerr;
        cmp = json_loads(cmp_txt, 0, &jerr);
        free(cmp_txt);
    }
    if (!cmp)
        cmp = json_object();
    json_t *out = json_object();
    json_object_set_new(out, "ok", json_boolean(done));
    if (!done)
        json_object_set_new(out, "error", json_string("conntrack compare timed out"));
    json_object_set_new(out, "compare", cmp); /* steals cmp's reference */
    char *txt = json_dumps(out, JSON_PRESERVE_ORDER | JSON_COMPACT);
    json_decref(out);
    return txt;
}

int hadc_ctl_step(hadc_ctx_t *ctx)
{
    if (ctx->ctl_fd < 0 && g_ctl_retry_at_ms &&
        hadc_now_ms() >= g_ctl_retry_at_ms) {
        int rc = hadc_ctl_rebind(ctx);
        g_ctl_retry_at_ms = rc >= 0 ? 0 : hadc_now_ms() + 1000;
    }
    for (size_t i = 0; i < CTL_PENDING_MAX; i++) {
        ctl_pending_t *p = &g_pending[i];
        if (p->fd < 0)
            continue;
        if (!p->reply) {
            bool done = hadc_conntrack_compare_done(ctx);
            if (!done && hadc_now_ms() < p->deadline_ms)
                continue; /* still running: never block the main loop */
            char *txt = compare_reply_json(ctx, done);
            if (!txt) {
                ctl_pending_release(p);
                continue;
            }
            size_t len = strlen(txt);
            p->reply = malloc(len + 2);
            if (!p->reply) {
                free(txt);
                ctl_pending_release(p);
                continue;
            }
            memcpy(p->reply, txt, len);
            p->reply[len] = '\n';
            p->reply[len + 1] = '\0';
            free(txt);
        }
        size_t len = strlen(p->reply);
        ssize_t n = write(p->fd, p->reply + p->off, len - p->off);
        if (n > 0) {
            p->off += (size_t)n;
        } else if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
            if (errno == EINTR)
                continue;
            continue; /* retry next loop iteration */
        } else if (n < 0) {
            hadc_warn("ctl: compare reply write failed: %s", strerror(errno));
            ctl_pending_release(p);
            continue;
        }
        if (p->off >= len)
            ctl_pending_release(p);
    }
    return 0;
}
