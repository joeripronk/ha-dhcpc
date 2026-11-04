/* Cluster module: heartbeat + versioned sync + role handling (plan §4).
 * M1 scaffold: transport bound, messages encoded/decoded as canonical JSON;
 * send/receive wired, cluster decisions still keepalived-driven. */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/log.h"
#include "internal.h"

static hadc_ctx_t *g_ctx;

static int send_json(hadc_ctx_t *ctx, const struct sockaddr_in *to, json_t *msg)
{
    char *txt = json_dumps(msg, JSON_PRESERVE_ORDER | JSON_COMPACT);
    if (!txt)
        return -1;
    ssize_t r = sendto(ctx->udp_fd, txt, strlen(txt), 0, (const struct sockaddr *)to, sizeof(*to));
    free(txt);
    json_decref(msg);
    return r < 0 ? -1 : 0;
}

static void load_msg_fields(hadc_ctx_t *ctx, json_t *m, hadc_msg_t *out)
{
    (void)ctx;
    memset(out, 0, sizeof(*out));
    const char *s;
    if ((s = json_string_value(json_object_get(m, "type"))))
        out->type = s; /* static strings; lifetime ends with json */
    if ((s = json_string_value(json_object_get(m, "origin"))))
        snprintf(out->origin, sizeof(out->origin), "%s", s);
    if ((s = json_string_value(json_object_get(m, "master_id"))))
        snprintf(out->master_id, sizeof(out->master_id), "%s", s);
    json_t *v = json_object_get(m, "lease_version");
    if (v && json_is_integer(v))
        out->lease_version = (uint64_t)json_integer_value(v);
    v = json_object_get(m, "acked_version");
    if (v && json_is_integer(v))
        out->acked_version = (uint64_t)json_integer_value(v);
    if ((s = json_string_value(json_object_get(m, "new_master"))))
        snprintf(out->new_master, sizeof(out->new_master), "%s", s);
}

static void peer_touch(hadc_ctx_t *ctx, const char *id)
{
    for (size_t i = 0; i < ctx->master.n_members; i++) {
        if (!strcmp(ctx->master.members[i].id, id)) {
            ctx->peers[i].alive = true;
            ctx->peers[i].last_seen_ms = (uint64_t)hadc_now_ms();
            snprintf(ctx->peers[i].id, HADC_NODE_ID_MAX, "%s", id);
            ctx->peers[i].sync_address = ctx->master.members[i].sync_address;
            ctx->n_peers = ctx->master.n_members;
            return;
        }
    }
}

static void udp_ready(hadc_ctx_t *ctx, int fd)
{
    char buf[4096];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &fromlen);
    if (n <= 0)
        return;
    buf[n] = '\0';

    json_error_t jerr;
    json_t *m = json_loads(buf, 0, &jerr);
    if (!m) {
        hadc_warn("sync: malformed datagram from %s:%d (ignored): %s", inet_ntoa(from.sin_addr),
                  ntohs(from.sin_port), jerr.text);
        return;
    }

    hadc_msg_t msg;
    load_msg_fields(ctx, m, &msg);
    peer_touch(ctx, msg.origin);

    if (!strcmp(msg.type, HADC_MSG_HEARTBEAT)) {
        hadc_dbg("sync: heartbeat from %s (master=%s, version=%llu)", msg.origin, msg.master_id,
                 (unsigned long long)msg.lease_version);
    } else if (!strcmp(msg.type, HADC_MSG_STATE_PUSH) || !strcmp(msg.type, HADC_MSG_FULL_STATE)) {
        /* M2: apply to executor, then ack. Scaffold: log only. */
        hadc_info("sync: %s from %s version=%llu (apply pending M2)", msg.type, msg.origin,
                  (unsigned long long)msg.lease_version);
    } else if (!strcmp(msg.type, HADC_MSG_APPLY_ACK)) {
        hadc_info("sync: apply-ack from %s acked_version=%llu", msg.origin,
                  (unsigned long long)msg.acked_version);
    } else if (!strcmp(msg.type, HADC_MSG_ROLE_CHANGE)) {
        hadc_info("sync: role_change from %s: master is now %s", msg.origin, msg.new_master);
        if (msg.new_master[0])
            snprintf(ctx->master.designated_master, HADC_NODE_ID_MAX, "%s", msg.new_master);
    } else {
        hadc_warn("sync: unknown message type '%s' from %s", msg.type, msg.origin);
    }
    json_decref(m);
}

int hadc_cluster_init(hadc_ctx_t *ctx)
{
    g_ctx = ctx;

    const hadc_member_t *self = NULL;
    for (size_t i = 0; i < ctx->master.n_members; i++)
        if (!strcmp(ctx->master.members[i].id, ctx->slave.self))
            self = &ctx->master.members[i];
    if (!self) {
        hadc_err("cluster: this node (%s) is not in master.conf members", ctx->slave.self);
        return -1;
    }

    ctx->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->udp_fd < 0) {
        hadc_err("cluster: socket: %s", strerror(errno));
        return -1;
    }
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(ctx->conf.cluster.port),
                                .sin_addr = self->sync_address };
    if (bind(ctx->udp_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        hadc_err("cluster: bind %s:%u: %s", inet_ntoa(addr.sin_addr),
                 (unsigned)ctx->conf.cluster.port, strerror(errno));
        return -1;
    }
    fcntl(ctx->udp_fd, F_SETFL, O_NONBLOCK);
    hadc_loop_add(ctx, ctx->udp_fd, udp_ready, 0);
    hadc_info("cluster: transport bound to %s:%u for node %s (v1 unauthenticated trusted LAN)",
              inet_ntoa(self->sync_address), (unsigned)ctx->conf.cluster.port, ctx->slave.self);
    return 0;
}

int hadc_cluster_step(hadc_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

/* Send a role_change cluster-wide (plan §4: every role change propagates). */
static void propagate_role(hadc_ctx_t *ctx)
{
    if (ctx->udp_fd < 0)
        return;
    for (size_t i = 0; i < ctx->master.n_members; i++) {
        if (!strcmp(ctx->master.members[i].id, ctx->slave.self))
            continue;
        json_t *m = json_pack("{s:s, s:s, s:s, s:I, s:s}", "type", HADC_MSG_ROLE_CHANGE, "origin",
                              ctx->slave.self, "master_id", ctx->master.designated_master,
                              "lease_version", (json_int_t)ctx->lease.version, "new_master",
                              ctx->master.designated_master);
        struct sockaddr_in to = { .sin_family = AF_INET,
                                  .sin_port = htons(ctx->conf.cluster.port),
                                  .sin_addr = ctx->master.members[i].sync_address };
        if (m && send_json(ctx, &to, m) != 0)
            hadc_warn("cluster: role_change send to %s failed", ctx->master.members[i].id);
    }
}

int hadc_cluster_promote(hadc_ctx_t *ctx, const char *new_master_id)
{
    const char *target = (new_master_id && *new_master_id) ? new_master_id : ctx->slave.self;
    if (!strcmp(ctx->master.designated_master, target)) {
        hadc_dbg("cluster: promote(%s) is idempotent (already master)", target);
        return 0;
    }
    snprintf(ctx->master.designated_master, HADC_NODE_ID_MAX, "%s", target);
    ctx->role = !strcmp(target, ctx->slave.self) ? HADC_ROLE_MASTER : HADC_ROLE_SLAVE;
    hadc_info("cluster: role change -> master=%s (this node: %s)", ctx->master.designated_master,
              ctx->role == HADC_ROLE_MASTER ? "MASTER" : "SLAVE");
    propagate_role(ctx);
    return 0;
}

int hadc_cluster_demote(hadc_ctx_t *ctx)
{
    /* A demote issued anywhere settles dual-master cluster-wide (plan §11.2).
     * v1: keepalived decides who the master is; we obey. */
    const char *target = ctx->master.designated_master;
    if (!strcmp(target, ctx->slave.self)) {
        hadc_dbg("cluster: demote requested on this node; v1 defers role choice to keepalived");
        return 0;
    }
    ctx->role = HADC_ROLE_SLAVE;
    hadc_info("cluster: demoted; master remains %s", target);
    propagate_role(ctx);
    return 0;
}

int hadc_cluster_push_state(hadc_ctx_t *ctx, const hadc_lease_t *lease)
{
    (void)ctx;
    (void)lease;
    /* M2: push to all members; slaves apply then ack. */
    return 0;
}
