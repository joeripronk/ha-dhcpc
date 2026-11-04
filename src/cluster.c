/* Cluster module: heartbeat + versioned sync + role handling (plan §4).
 * M2: heartbeats are sent cluster-wide, master pushes lease state on change,
 * slaves pre-apply then ack; role changes propagate. Decisions stay
 * keepalived-driven (v1: dead-master/quorum are alarms only). */
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
#include "ha-dhcpc/dhcpcore.h"
#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/log.h"
#include "ha-dhcpc/persist.h"
#include "internal.h"

static hadc_ctx_t *g_ctx;

static void (*g_role_hook)(void *arg, hadc_role_t old_role, hadc_role_t new_role);
static void *g_role_hook_arg;
static uint64_t g_cluster_start_ms;

void hadc_cluster_set_role_hook(void (*fn)(void *arg, hadc_role_t old_role,
                                           hadc_role_t new_role), void *arg)
{
    g_role_hook = fn;
    g_role_hook_arg = arg;
}

static void set_role(hadc_ctx_t *ctx, hadc_role_t new_role)
{
    hadc_role_t old_role = ctx->role;
    if (old_role == new_role)
        return;
    ctx->role = new_role;
    if (g_role_hook != NULL)
        g_role_hook(g_role_hook_arg, old_role, new_role);
}

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

static const hadc_member_t *member_by_id(hadc_ctx_t *ctx, const char *id)
{
    for (size_t i = 0; i < ctx->master.n_members; i++)
        if (!strcmp(ctx->master.members[i].id, id))
            return &ctx->master.members[i];
    return NULL;
}

static hadc_peer_t *peer_entry(hadc_ctx_t *ctx, const char *id)
{
    for (size_t i = 0; i < ctx->n_peers; i++)
        if (!strcmp(ctx->peers[i].id, id))
            return &ctx->peers[i];
    return NULL;
}

static int send_to_member(hadc_ctx_t *ctx, const hadc_member_t *m, json_t *msg)
{
    if (!msg)
        return -1;
    if (ctx->udp_fd < 0 || !m) {
        json_decref(msg);
        return -1;
    }
    struct sockaddr_in to = { .sin_family = AF_INET,
                               .sin_port = htons(ctx->conf.cluster.port),
                               .sin_addr = m->sync_address };
    if (send_json(ctx, &to, msg) != 0) {
        hadc_warn("cluster: send to %s failed", m->id);
        return -1;
    }
    return 0;
}

static void put_addr(json_t *obj, const char *key, struct in_addr a)
{
    char buf[64];
    json_object_set_new(obj, key, json_string(inet_ntop(AF_INET, &a, buf, sizeof(buf))));
}

static void get_addr(json_t *obj, const char *key, struct in_addr *out)
{
    json_t *v = json_object_get(obj, key);
    if (v && json_is_string(v))
        inet_pton(AF_INET, json_string_value(v), out);
}

static json_t *lease_json(const hadc_lease_t *l)
{
    char hex[65];
    json_t *dns = json_array();

    for (size_t i = 0; i < 32; i++)
        sprintf(hex + 2 * i, "%02x", l->config_hash[i]);
    for (size_t i = 0; i < l->n_dns; i++) {
        char buf[64];
        json_array_append_new(dns, json_string(inet_ntop(AF_INET, &l->dns[i], buf, sizeof(buf))));
    }
    json_t *o = json_pack("{s:s, s:b, s:s, s:s, s:s, s:s, s:o, s:I, s:I, s:I, s:s}",
                           "state", hadc_lease_state_name(l->state), "retention_active",
                           (int)l->retention_active, "address", "", "netmask", "", "gateway", "",
                           "server_id", "", "dns", dns, "t1_remaining_s",
                           (json_int_t)l->t1_remaining_s, "t2_remaining_s",
                           (json_int_t)l->t2_remaining_s, "t3_remaining_s",
                           (json_int_t)l->t3_remaining_s, "config_hash", hex);
    if (!o) {
        json_decref(dns);
        return NULL;
    }
    put_addr(o, "address", l->address);
    put_addr(o, "netmask", l->netmask);
    put_addr(o, "gateway", l->gateway);
    put_addr(o, "server_id", l->server_id);
    return o;
}

static hadc_lease_state_t name_to_state(const char *n)
{
    if (!strcmp(n, "BOUND"))        return HADC_LEASE_BOUND;
    if (!strcmp(n, "RENEW"))        return HADC_LEASE_RENEW;
    if (!strcmp(n, "REBIND"))       return HADC_LEASE_REBIND;
    if (!strcmp(n, "RETAINED"))     return HADC_LEASE_RETAINED;
    if (!strcmp(n, "INIT-REBOOT"))  return HADC_LEASE_INIT_REBOOT;
    if (!strcmp(n, "INIT-SELECT"))  return HADC_LEASE_INIT_SELECT;
    return HADC_LEASE_NONE;
}

static void parse_lease(json_t *lj, hadc_lease_t *out)
{
    json_t *v;

    if (!lj || !json_is_object(lj))
        return;
    if ((v = json_object_get(lj, "state")) && json_is_string(v))
        out->state = name_to_state(json_string_value(v));
    if ((v = json_object_get(lj, "retention_active")) && json_is_boolean(v))
        out->retention_active = json_is_true(v);
    get_addr(lj, "address", &out->address);
    get_addr(lj, "netmask", &out->netmask);
    get_addr(lj, "gateway", &out->gateway);
    get_addr(lj, "server_id", &out->server_id);
    json_t *dns = json_object_get(lj, "dns");
    if (dns && json_is_array(dns)) {
        size_t idx;
        json_t *e;
        json_array_foreach(dns, idx, e) {
            if (json_is_string(e) && out->n_dns < HADC_DNS_MAX &&
                inet_pton(AF_INET, json_string_value(e), &out->dns[out->n_dns]) == 1)
                out->n_dns++;
        }
    }
    if ((v = json_object_get(lj, "t1_remaining_s")) && json_is_integer(v))
        out->t1_remaining_s = (uint32_t)json_integer_value(v);
    if ((v = json_object_get(lj, "t2_remaining_s")) && json_is_integer(v))
        out->t2_remaining_s = (uint32_t)json_integer_value(v);
    if ((v = json_object_get(lj, "t3_remaining_s")) && json_is_integer(v))
        out->t3_remaining_s = (uint32_t)json_integer_value(v);
    if ((v = json_object_get(lj, "config_hash")) && json_is_string(v) &&
        strlen(json_string_value(v)) == 64) {
        for (size_t i = 0; i < 32; i++) {
            unsigned b;
            if (sscanf(json_string_value(v) + 2 * i, "%2x", &b) != 1)
                break;
            out->config_hash[i] = (uint8_t)b;
        }
    }
}

static json_t *build_msg(hadc_ctx_t *ctx, const char *type, int with_lease)
{
    json_t *m = json_pack("{s:s, s:s, s:s, s:I}", "type", type, "origin", ctx->slave.self,
                           "master_id", ctx->master.designated_master, "lease_version",
                           (json_int_t)ctx->lease.version);
    if (!m)
        return NULL;
    if (with_lease) {
        json_t *lj = lease_json(&ctx->lease);
        if (lj)
            json_object_set_new(m, "lease", lj);
    }
    return m;
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
    parse_lease(json_object_get(m, "lease"), &out->lease);
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

/* Slave pre-apply: adopt the master's lease state, apply via executor, ack. */
static void slave_adopt_and_ack(hadc_ctx_t *ctx, const hadc_msg_t *msg, int is_full)
{
    hadc_desired_t desired;
    const hadc_member_t *master = member_by_id(ctx, msg->origin);

    ctx->lease = msg->lease;
    ctx->lease.version = msg->lease_version;
    hadc_executor_desired(ctx, &ctx->lease, &desired);
    hadc_executor_apply(ctx, &desired, hadc_lease_state_name(ctx->lease.state));
    ctx->acked_version = ctx->lease.version;
    hadc_persist_save(ctx);
    hadc_dhcpcore_write_lease_file(ctx, &ctx->lease); /* for renew-only duty */

    hadc_info("sync: %s v%llu adopted from %s; applied and acked",
              is_full ? "full_state" : "state_push",
              (unsigned long long)ctx->lease.version, msg->origin);

    json_t *ack = json_pack("{s:s, s:s, s:s, s:I, s:I}", "type", HADC_MSG_APPLY_ACK, "origin",
                             ctx->slave.self, "master_id", ctx->master.designated_master,
                             "lease_version", (json_int_t)ctx->lease.version, "acked_version",
                             (json_int_t)ctx->acked_version);
    send_to_member(ctx, master, ack);
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
    int first_seen = peer_entry(ctx, msg.origin) == NULL;
    peer_touch(ctx, msg.origin);

    if (!strcmp(msg.type, HADC_MSG_HEARTBEAT)) {
        hadc_dbg("sync: heartbeat from %s (master=%s, version=%llu)", msg.origin, msg.master_id,
                 (unsigned long long)msg.lease_version);
        if (ctx->role == HADC_ROLE_SLAVE && !strcmp(msg.origin, ctx->master.designated_master) &&
            strcmp(ctx->master.designated_master, ctx->slave.self)) {
            int gap = first_seen || msg.lease_version > ctx->lease.version + 1;
            if (gap) {
                hadc_info("sync: version gap (theirs=%llu ours=%llu%s); requesting full state",
                          (unsigned long long)msg.lease_version,
                          (unsigned long long)ctx->lease.version,
                          first_seen ? ", join" : "");
                json_t *req = json_pack("{s:s, s:s, s:s, s:I}", "type", HADC_MSG_FULL_STATE_REQ,
                                        "origin", ctx->slave.self, "master_id",
                                        ctx->master.designated_master, "lease_version",
                                        (json_int_t)ctx->lease.version);
                send_to_member(ctx, member_by_id(ctx, msg.origin), req);
            }
        }
    } else if (!strcmp(msg.type, HADC_MSG_STATE_PUSH) || !strcmp(msg.type, HADC_MSG_FULL_STATE)) {
        if (ctx->role == HADC_ROLE_SLAVE && !strcmp(msg.origin, ctx->master.designated_master))
            slave_adopt_and_ack(ctx, &msg, !strcmp(msg.type, HADC_MSG_FULL_STATE));
        else
            hadc_info("sync: %s from %s version=%llu (ignored: role/master mismatch)", msg.type,
                      msg.origin, (unsigned long long)msg.lease_version);
    } else if (!strcmp(msg.type, HADC_MSG_APPLY_ACK)) {
        hadc_peer_t *p = peer_entry(ctx, msg.origin);
        if (p && msg.acked_version >= p->acked_version)
            p->acked_version = msg.acked_version;
        hadc_info("sync: apply-ack from %s acked_version=%llu", msg.origin,
                  (unsigned long long)msg.acked_version);
    } else if (!strcmp(msg.type, HADC_MSG_FULL_STATE_REQ)) {
        if (ctx->role == HADC_ROLE_MASTER && strcmp(msg.origin, ctx->slave.self)) {
            json_t *rep = build_msg(ctx, HADC_MSG_FULL_STATE, 1);
            send_to_member(ctx, member_by_id(ctx, msg.origin), rep);
            hadc_info("sync: full_state sent to %s", msg.origin);
        }
    } else if (!strcmp(msg.type, HADC_MSG_ROLE_CHANGE)) {
        hadc_info("sync: role_change from %s: master is now %s", msg.origin, msg.new_master);
        if (msg.new_master[0]) {
            snprintf(ctx->master.designated_master, HADC_NODE_ID_MAX, "%s", msg.new_master);
            set_role(ctx, !strcmp(msg.new_master, ctx->slave.self) ? HADC_ROLE_MASTER
                                                                   : HADC_ROLE_SLAVE);
            hadc_persist_save(ctx);
        }
    } else {
        hadc_warn("sync: unknown message type '%s' from %s", msg.type, msg.origin);
    }
    json_decref(m);
}

int hadc_cluster_init(hadc_ctx_t *ctx)
{
    g_ctx = ctx;
    g_cluster_start_ms = (uint64_t)hadc_now_ms();

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

/* Heartbeat tick (called by the daemon every heartbeat_ms, all roles). */
void hadc_cluster_heartbeat(hadc_ctx_t *ctx)
{
    static uint64_t last_alarm_ms;

    for (size_t i = 0; i < ctx->master.n_members; i++) {
        const hadc_member_t *m = &ctx->master.members[i];
        if (!strcmp(m->id, ctx->slave.self))
            continue;
        json_t *hb = build_msg(ctx, HADC_MSG_HEARTBEAT, 1);
        send_to_member(ctx, m, hb);
    }

    /* Dead-master detection: alarm-only in v1 (no self-promotion). */
    if (ctx->role != HADC_ROLE_MASTER && ctx->master.designated_master[0] &&
        strcmp(ctx->master.designated_master, ctx->slave.self)) {
        hadc_peer_t *p = peer_entry(ctx, ctx->master.designated_master);
        uint64_t now = (uint64_t)hadc_now_ms();
        if (p && p->last_seen_ms != 0 &&
            now - p->last_seen_ms > ctx->conf.cluster.election_deadline_ms &&
            now - last_alarm_ms >= ctx->conf.cluster.election_deadline_ms) {
            last_alarm_ms = now;
            hadc_warn("ALARM: no heartbeat from master %s for %llums (deadline %ums); "
                      "v1 alarms only, no self-promotion",
                      p->id, (unsigned long long)(now - p->last_seen_ms),
                      (unsigned)ctx->conf.cluster.election_deadline_ms);
        }
    }

    hadc_cluster_elect_check(ctx);
}

/* Default-role bootstrap election: with default_role=master and no master
 * known, a node self-promotes when it is a single node, when every member is
 * alive and none is master (all slaves), or once cluster_timeout_ms has
 * elapsed (partial view: dual-master partitions still alarm). Election is by
 * priority (mirrored in master.conf), ties by lowest node id; the winner
 * announces via the normal role_change propagation path. */
void hadc_cluster_elect_check(hadc_ctx_t *ctx)
{
    bool all_alive, timeout_path;
    const char *winner;
    int wprio;

    if (!ctx->conf.default_role_master)
        return;
    if (ctx->master.designated_master[0] != '\0')
        return; /* a master is known: configured or elected */
    if (ctx->role != HADC_ROLE_SLAVE)
        return;

    all_alive = true;
    for (size_t i = 0; i < ctx->master.n_members; i++) {
        hadc_peer_t *p;
        if (!strcmp(ctx->master.members[i].id, ctx->slave.self))
            continue;
        p = peer_entry(ctx, ctx->master.members[i].id);
        if (!p || !p->alive)
            all_alive = false;
    }
    timeout_path = ctx->conf.cluster.cluster_timeout_ms > 0 &&
        (uint64_t)hadc_now_ms() - g_cluster_start_ms >=
            ctx->conf.cluster.cluster_timeout_ms;
    if (!all_alive && !timeout_path)
        return;

    winner = ctx->slave.self;
    wprio = ctx->slave.priority;
    for (size_t i = 0; i < ctx->master.n_members; i++) {
        const hadc_member_t *m = &ctx->master.members[i];
        hadc_peer_t *p;
        if (!strcmp(m->id, ctx->slave.self))
            continue;
        p = peer_entry(ctx, m->id);
        if (!p || !p->alive)
            continue; /* not visible: cannot vote in its absence */
        if (m->priority > wprio ||
            (m->priority == wprio && strcmp(m->id, winner) < 0)) {
            wprio = m->priority;
            winner = m->id;
        }
    }
    if (strcmp(winner, ctx->slave.self) != 0)
        return;

    hadc_info("cluster: default-role election: promoting self (priority %d, %s)", wprio,
              all_alive ? "all members alive" : "cluster timeout elapsed");
    hadc_cluster_promote(ctx, ctx->slave.self);
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
    set_role(ctx, !strcmp(target, ctx->slave.self) ? HADC_ROLE_MASTER : HADC_ROLE_SLAVE);
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
    set_role(ctx, HADC_ROLE_SLAVE);
    hadc_info("cluster: demoted; master remains %s", target);
    propagate_role(ctx);
    return 0;
}

int hadc_cluster_push_state(hadc_ctx_t *ctx, const hadc_lease_t *lease)
{
    if (ctx->udp_fd < 0 || ctx->role != HADC_ROLE_MASTER)
        return 0;
    for (size_t i = 0; i < ctx->master.n_members; i++) {
        const hadc_member_t *m = &ctx->master.members[i];
        if (!strcmp(m->id, ctx->slave.self))
            continue;
        json_t *msg = json_pack("{s:s, s:s, s:s, s:I}", "type", HADC_MSG_STATE_PUSH, "origin",
                                ctx->slave.self, "master_id", ctx->master.designated_master,
                                "lease_version", (json_int_t)lease->version);
        json_t *lj = msg ? lease_json(lease) : NULL;
        if (lj)
            json_object_set_new(msg, "lease", lj);
        if (msg && send_to_member(ctx, m, msg) == 0)
            hadc_info("sync: state_push v%llu sent to %s",
                      (unsigned long long)lease->version, m->id);
    }
    return 0;
}
