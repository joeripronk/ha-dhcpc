/* Control interface: unix socket, plaintext commands, JSON replies (plan §3/§4).
 * Idempotent, logged, auditable. */
#define _GNU_SOURCE

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
#include <unistd.h>

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/conntrack.h"
#include "ha-dhcpc/ctl.h"
#include "ha-dhcpc/dhcpcore.h"
#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/lease.h"
#include "ha-dhcpc/log.h"
#include "ha-dhcpc/reload.h"
#include "ha-dhcpc/routing.h"
#include "internal.h"

static const char *role_name(hadc_role_t r)
{
    switch (r) {
    case HADC_ROLE_MASTER:    return "master";
    case HADC_ROLE_SLAVE:     return "slave";
    case HADC_ROLE_PROMOTING: return "promoting";
    case HADC_ROLE_DEMOTING:  return "demoting";
    default:                  return "unknown";
    }
}

static char g_ctl_path[HADC_PATH_MAX]; /* where ctl_fd is bound (rebind check) */

static json_t *status_object(hadc_ctx_t *ctx)
{
    bool gr_active = hadc_cluster_graceful_active(ctx);
    json_t *o = json_pack(
        "{s:s, s:s, s:s, s:I, s:b, s:s, s:o}", "role", role_name(ctx->role), "self",
        ctx->conf.self, "master", ctx->conf.designated_master, "lease_version",
        (json_int_t)ctx->lease.version, "retention", (int)ctx->lease.retention_active,
        "conf_sha256", ctx->conf.sha256, "timers",
        json_pack("{s:I, s:I}", "heartbeat_ms", (json_int_t)ctx->conf.cluster.heartbeat_ms,
                  "election_deadline_ms", (json_int_t)ctx->conf.cluster.election_deadline_ms));
    if (!o)
        return NULL;
    json_t *members = json_array();
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        char addr[64];
        snprintf(addr, sizeof(addr), "%s", inet_ntoa(ctx->conf.members[i].sync_address));
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
    json_object_set_new(o, "members", members);
    json_t *cluster = json_array();
    for (size_t i = 0; i < ctx->conf.cluster.n_ifaces; i++) {
        const hadc_cluster_if_t *ci = &ctx->conf.cluster.ifaces[i];
        json_t *addrs = json_array();
        for (size_t j = 0; j < ci->n_addrs; j++) {
            char buf[64];
            snprintf(buf, sizeof(buf), "%s/%u", inet_ntoa(ci->addrs[j].address),
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

static void handle_command(hadc_ctx_t *ctx, const char *line, int reply_fd)
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
                      role_name(ctx->role));
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
                      role_name(ctx->role));
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
                      role_name(ctx->role));
            reply = "{\"ok\":false,\"error\":\"not master\"}";
        } else if (hadc_dhcpcore_force_discover(ctx) != 0) {
            reply = "{\"ok\":false,\"error\":\"newip failed\"}";
        } else {
            ctx->newip_old_addr = ctx->lease.address;
            ctx->newip_pending = true;
            hadc_info("ctl: newip forced a fresh DISCOVER (old=%s, abort_tcp=%s)",
                      ctx->newip_old_addr.s_addr ? inet_ntoa(ctx->newip_old_addr) : "none",
                      ctx->conf.apply.abort_tcp_on_newip ? "on" : "off");
        }
    } else if (!strcmp(cmd, "graceful-restart")) {
        if (ctx->role != HADC_ROLE_MASTER) {
            hadc_warn("ctl: graceful-restart refused here (role %s); only the master sets it",
                      role_name(ctx->role));
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
        } else {
            reply = "{\"ok\":false,\"error\":\"usage: conntrack resync\"}";
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
    int c = accept(fd, NULL, NULL);
    if (c < 0)
        return;
    char line[256];
    ssize_t n = read(c, line, sizeof(line) - 1);
    if (n > 0) {
        line[n] = '\0';
        line[strcspn(line, "\r\n")] = '\0';
        handle_command(ctx, line, c);
    }
    close(c);
}

int hadc_ctl_init(hadc_ctx_t *ctx)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", ctx->conf.ctl_socket);

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
    hadc_loop_add(ctx, ctx->ctl_fd, ctl_ready, 0);
    snprintf(g_ctl_path, sizeof(g_ctl_path), "%s", addr.sun_path);
    hadc_info("ctl: listening on %s", ctx->conf.ctl_socket);
    return 0;
}

/* Move the control socket after a reload changed ctl_socket; 0 when unchanged. */
int hadc_ctl_rebind(hadc_ctx_t *ctx)
{
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", ctx->conf.ctl_socket);
    if (ctx->ctl_fd >= 0 && strcmp(addr.sun_path, g_ctl_path) == 0)
        return 0;

    if (ctx->ctl_fd >= 0) {
        hadc_loop_del(ctx, ctx->ctl_fd);
        close(ctx->ctl_fd);
        ctx->ctl_fd = -1;
        unlink(g_ctl_path);
    }
    ctx->ctl_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (ctx->ctl_fd < 0) {
        hadc_err("ctl: socket: %s", strerror(errno));
        return -1;
    }
    if (bind(ctx->ctl_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        hadc_err("ctl: bind %s: %s", ctx->conf.ctl_socket, strerror(errno));
        close(ctx->ctl_fd);
        ctx->ctl_fd = -1;
        return -1;
    }
    listen(ctx->ctl_fd, 8);
    hadc_loop_add(ctx, ctx->ctl_fd, ctl_ready, 0);
    snprintf(g_ctl_path, sizeof(g_ctl_path), "%s", addr.sun_path);
    hadc_info("ctl: control socket moved to %s", g_ctl_path);
    return 1;
}

int hadc_ctl_step(hadc_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}
