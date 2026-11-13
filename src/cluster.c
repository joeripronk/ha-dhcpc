/* Cluster module: heartbeat + versioned sync + role handling (plan §4).
 * Heartbeats are sent cluster-wide, the master pushes lease state on change,
 * slaves pre-apply then ack, and role changes propagate. Failover is built in:
 * a dead master is replaced by the highest-priority live member once quorum is
 * satisfied, and every master owns the configured cluster addresses. */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/dhcpcore.h"
#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/log.h"
#include "ha-dhcpc/persist.h"
#include "ha-dhcpc/reload.h"
#include "internal.h"

/* Guards the fields the heartbeat thread reads (role, lease.version,
 * graceful_restart_until_ms). Keep critical sections tight: lock only the field
 * write/read, never across a call that itself locks. */
#define HB_LOCK(ctx)   pthread_mutex_lock(&(ctx)->hb_lock)
#define HB_UNLOCK(ctx) pthread_mutex_unlock(&(ctx)->hb_lock)

static hadc_ctx_t *g_ctx;

static void (*g_role_hook)(void *arg, hadc_role_t old_role, hadc_role_t new_role);
static void *g_role_hook_arg;
static uint64_t g_cluster_start_ms;
static uint64_t g_no_elect_until_ms; /* manual demote cooldown */
static struct sockaddr_in g_bound; /* what udp_fd is bound to (rebind check) */

static void propagate_role(hadc_ctx_t *ctx);
static bool beats(const hadc_member_t *a, const char *b_id, int b_prio);
static const hadc_member_t *election_winner(hadc_ctx_t *ctx);
int cluster_startup_claim(hadc_ctx_t *ctx, char *out, size_t outsz);
static bool master_is_alive(hadc_ctx_t *ctx, const char *id);
static void age_peers(hadc_ctx_t *ctx);
static uint64_t realtime_ms(void);
static int send_json(hadc_ctx_t *ctx, const struct sockaddr_in *to, json_t *msg);

static void udp_ready(hadc_ctx_t *ctx, int fd);

static const char *role_name(hadc_role_t r)
{
    return r == HADC_ROLE_MASTER ? "master" : (r == HADC_ROLE_SLAVE ? "slave" : "unknown");
}

/* Compact binary heartbeat (minimum-frame sized): 16-byte payload, 64-byte
 * Ethernet frame. Members are referenced by index into the shared config, so
 * index identity assumes the same shared document cluster-wide; a sender whose
 * index is unknown here is skipped by the assertion paths, which are driven by
 * role_change propagation and the conf-sync push instead.
 *
 *   0  type: 0 = heartbeat (JSON datagrams start with '{', so 0 is the
 *      discriminator for the whole wire)
 *   1  origin member index (255 = unknown)
 *   2  master member index (254 = no master, 255 = unknown)
 *   3  role wire code (HADC_WIRE_ROLE_*)
 *   4  lease_version, big-endian u64
 *   12 ts_ms, big-endian u32 low bits of CLOCK_REALTIME ms (decoded to the
 *      nearest full ms to our clock, so the ~49-day wrap is harmless)
 */
#define HADC_WIRE_HB_LEN       16
#define HADC_WIRE_IDX_UNKNOWN  255
#define HADC_WIRE_IDX_NONE     254


#define HADC_MSG_GRACEFUL "graceful_restart"

#define HADC_GRACEFUL_WINDOW_MS 180000ULL

bool hadc_cluster_graceful_active(hadc_ctx_t *ctx)
{
    if (!ctx || ctx->graceful_restart_until_ms == 0)
        return false;
    uint64_t now = realtime_ms();
    if (now >= ctx->graceful_restart_until_ms) {
        /* expired: clear lazily */
        HB_LOCK(ctx);
        ctx->graceful_restart_until_ms = 0;
        HB_UNLOCK(ctx);
        return false;
    }
    return true;
}

void hadc_cluster_broadcast_graceful(hadc_ctx_t *ctx)
{
    if (ctx->udp_fd < 0)
        return;
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        const hadc_member_t *m = &ctx->conf.members[i];
        if (!strcmp(m->id, ctx->conf.self))
            continue;
        json_t *msg = json_pack("{s:s, s:s, s:s, s:I, s:I}", "type", HADC_MSG_GRACEFUL,
                                "origin", ctx->conf.self, "master_id",
                                ctx->conf.designated_master, "lease_version",
                                (json_int_t)ctx->lease.version, "graceful_restart_until_ms",
                                (json_int_t)ctx->graceful_restart_until_ms);
        if (!msg)
            continue;
        json_object_set_new(msg, "conf_sha256", json_string(ctx->conf.sha256));
        json_object_set_new(msg, "ts_ms", json_integer((json_int_t)realtime_ms()));
        json_object_set_new(msg, "role", json_string(role_name(ctx->role)));
        struct sockaddr_in to = { .sin_family = AF_INET,
                                  .sin_port = htons(ctx->conf.cluster.port),
                                  .sin_addr = m->sync_address };
        if (send_json(ctx, &to, msg) != 0)
            hadc_warn("cluster: graceful_restart send to %s failed", m->id);
    }
}

static void graceful_adopt(hadc_ctx_t *ctx, uint64_t until_ms, const char *from)
{
    if (until_ms == ctx->graceful_restart_until_ms)
        return;
    /* adopt announced state (enable or cancel/expiry) */
    HB_LOCK(ctx);
    ctx->graceful_restart_until_ms = until_ms;
    HB_UNLOCK(ctx);
    if (until_ms == 0)
        hadc_info("cluster: graceful restart cancelled (from %s)", from ? from : "?");
    else
        hadc_info("cluster: graceful restart active until %llu ms realtime (from %s)",
                  (unsigned long long)until_ms, from ? from : "?");
    hadc_persist_save(ctx);
}

int hadc_cluster_set_graceful_restart(hadc_ctx_t *ctx, bool enable)
{
    uint64_t until = 0;
    if (enable)
        until = realtime_ms() + HADC_GRACEFUL_WINDOW_MS;
    if (until == ctx->graceful_restart_until_ms && enable == hadc_cluster_graceful_active(ctx))
        return 0;
    HB_LOCK(ctx);
    ctx->graceful_restart_until_ms = until;
    HB_UNLOCK(ctx);
    if (enable)
        hadc_info("cluster: graceful restart enabled for %llu ms (no master switches)",
                  (unsigned long long)HADC_GRACEFUL_WINDOW_MS);
    else
        hadc_info("cluster: graceful restart disabled");
    hadc_persist_save(ctx);
    /* burst so peers persist before restarts; heartbeats/JSON carry it too */
    for (int i = 0; i < 5; i++) {
        hadc_cluster_broadcast_graceful(ctx);
        if (i < 4)
            usleep(50000);
    }
    return 0;
}


static size_t put_be(uint8_t *p, uint64_t v, size_t n)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)(v >> (8 * (n - 1 - i)));
    return n;
}

static uint64_t get_be(const uint8_t *p, size_t n)
{
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++)
        v = (v << 8) | p[i];
    return v;
}

/* Reconstruct a full CLOCK_REALTIME ms from the 32-bit wire field: the nearest
 * value to our own clock (peers are seconds apart, never ~24 days apart), so a
 * wrap does not turn the timestamp into garbage. */
static uint64_t unwrap_ms(uint32_t low32)
{
    uint64_t now = realtime_ms();
    int32_t delta = (int32_t)(uint32_t)(low32 - (uint32_t)now);
    return (uint64_t)((int64_t)now + delta);
}

static int member_index(const hadc_ctx_t *ctx, const char *id)
{
    if (!id[0])
        return HADC_WIRE_IDX_NONE;
    for (size_t i = 0; i < ctx->conf.n_members; i++)
        if (!strcmp(ctx->conf.members[i].id, id))
            return (int)i;
    return HADC_WIRE_IDX_UNKNOWN;
}

static const char *member_id_by_index(const hadc_ctx_t *ctx, int idx)
{
    if (idx == HADC_WIRE_IDX_NONE)
        return "";
    if (idx < 0 || idx >= (int)ctx->conf.n_members)
        return NULL;
    return ctx->conf.members[idx].id;
}

static void build_bin_heartbeat(const hadc_ctx_t *ctx, uint8_t *out)
{
    memset(out, 0, HADC_WIRE_HB_LEN);
    out[1] = (uint8_t)member_index(ctx, ctx->conf.self);
    out[2] = (uint8_t)member_index(ctx, ctx->conf.designated_master);
    out[3] = (uint8_t)ctx->role; /* matches the HADC_WIRE_ROLE_* codes */
    put_be(out + 4, ctx->lease.version, 8);
    put_be(out + 12, realtime_ms() & 0xffffffffu, 4);
}

static int decode_bin_heartbeat(const hadc_ctx_t *ctx, const uint8_t *p, size_t len,
                                hadc_msg_t *out)
{
    if (len != HADC_WIRE_HB_LEN || p[0] != 0)
        return -1;
    const char *id;
    memset(out, 0, sizeof(*out));
    out->type = HADC_MSG_HEARTBEAT;
    id = member_id_by_index(ctx, p[1]);
    if (!id)
        return -1; /* sender is not in our shared copy: indices disagree */
    snprintf(out->origin, sizeof(out->origin), "%s", id);
    id = member_id_by_index(ctx, p[2]);
    if (id)
        snprintf(out->master_id, sizeof(out->master_id), "%s", id);
    if (p[3] == HADC_WIRE_ROLE_MASTER)
        snprintf(out->role, sizeof(out->role), "master");
    else if (p[3] == HADC_WIRE_ROLE_SLAVE)
        snprintf(out->role, sizeof(out->role), "slave");
    else
        snprintf(out->role, sizeof(out->role), "unknown");
    out->lease_version = get_be(p + 4, 8);
    out->ts_ms = unwrap_ms((uint32_t)get_be(p + 12, 4));
    return 0;
}

/* CLOCK_REALTIME ms — the clock messages timestamp (heartbeats carry it so a
 * starting node can sync and peers can spot drift; timers stay monotonic). */
static uint64_t realtime_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Step the clock during startup timesync / alarm at runtime when a peer's
 * clock differs from ours by more than this many milliseconds. */
#define HADC_TIMESYNC_STEP_MS 2000

/* Startup-timesync sanity: a peer clock that predates this has not been set
 * (unsynced boot clock); its vote is ignored. */
#define HADC_TIMESYNC_MIN_MS 1767225600000LL /* 2026-01-01T00:00:00Z */

void hadc_cluster_set_role_hook(void (*fn)(void *arg, hadc_role_t old_role,
                                           hadc_role_t new_role), void *arg)
{
    g_role_hook = fn;
    g_role_hook_arg = arg;
}

static void send_heartbeats_now(hadc_ctx_t *ctx);

static void set_role(hadc_ctx_t *ctx, hadc_role_t new_role)
{
    hadc_role_t old_role;
    HB_LOCK(ctx);
    old_role = ctx->role;
    if (old_role == new_role) {
        HB_UNLOCK(ctx);
        return;
    }
    ctx->role = new_role;
    HB_UNLOCK(ctx);
    if (g_role_hook != NULL)
        g_role_hook(g_role_hook_arg, old_role, new_role);
    send_heartbeats_now(ctx);
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

static int send_bytes(hadc_ctx_t *ctx, const struct sockaddr_in *to, const uint8_t *buf,
                      size_t len)
{
    if (ctx->udp_fd < 0)
        return -1;
    ssize_t r = sendto(ctx->udp_fd, buf, len, 0, (const struct sockaddr *)to, sizeof(*to));
    return r < 0 ? -1 : 0;
}

static void send_heartbeats_now(hadc_ctx_t *ctx)
{
    if (ctx->udp_fd < 0)
        return;
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        const hadc_member_t *m = &ctx->conf.members[i];
        uint8_t hb[HADC_WIRE_HB_LEN];
        if (!strcmp(m->id, ctx->conf.self))
            continue;
        build_bin_heartbeat(ctx, hb);
        struct sockaddr_in to = { .sin_family = AF_INET,
                                   .sin_port = htons(ctx->conf.cluster.port),
                                   .sin_addr = m->sync_address };
        if (send_bytes(ctx, &to, hb, sizeof(hb)) != 0)
            hadc_warn("cluster: send heartbeat to %s failed", m->id);
    }
}

/* Heartbeat send cadence + self-monitor watchdog, on its own thread so its
 * cadence is never blocked by main-loop work (executor/OSPF/persist/netlink).
 * The wire packet is built from a lock-protected snapshot; send and watchdog run
 * outside the lock. The thread never mutates shared state: a genuine stall
 * (send gap past heartbeat_ms + gap_ms) is handed to the main loop via the
 * self-pipe, which performs the demote. A lone-master/standalone node has nobody
 * to hand to, so it runs no cadence here. */
static void *hb_thread_main(void *arg)
{
    hadc_ctx_t *ctx = arg;
    uint32_t cadence_ms = ctx->conf.cluster.heartbeat_ms;
    uint32_t gap_ms = ctx->conf.cluster.self_demote_gap_ms;
    uint64_t last_send_ms = 0;

    for (;;) {
        struct timespec nap = { .tv_sec = cadence_ms / 1000,
                                .tv_nsec = (long)(cadence_ms % 1000) * 1000000 };
        clock_nanosleep(CLOCK_MONOTONIC, 0, &nap, NULL);

        uint8_t role, master_idx, self_idx;
        uint64_t lease_version;
        bool graceful;
        pthread_mutex_lock(&ctx->hb_lock);
        role = (uint8_t)ctx->role;
        lease_version = ctx->lease.version;
        master_idx = (uint8_t)member_index(ctx, ctx->conf.designated_master);
        self_idx = (uint8_t)member_index(ctx, ctx->conf.self);
        graceful = (ctx->graceful_restart_until_ms != 0 &&
                    realtime_ms() < ctx->graceful_restart_until_ms);
        pthread_mutex_unlock(&ctx->hb_lock);

        uint8_t hb[HADC_WIRE_HB_LEN];
        memset(hb, 0, sizeof(hb));
        hb[1] = self_idx;
        hb[2] = master_idx;
        hb[3] = role;
        put_be(hb + 4, lease_version, 8);
        put_be(hb + 12, (uint64_t)realtime_ms() & 0xffffffffu, 4);

        uint64_t now_ms = (uint64_t)realtime_ms();
        for (size_t i = 0; i < ctx->conf.n_members; i++) {
            const hadc_member_t *m = &ctx->conf.members[i];
            if (!strcmp(m->id, ctx->conf.self))
                continue;
            struct sockaddr_in to = { .sin_family = AF_INET,
                                      .sin_port = htons(ctx->conf.cluster.port),
                                      .sin_addr = m->sync_address };
            send_bytes(ctx, &to, hb, sizeof(hb));
        }

        if (gap_ms == 0) { /* watchdog off */
            last_send_ms = now_ms;
            continue;
        }
        uint64_t threshold_ms = (uint64_t)cadence_ms + gap_ms;
        if (last_send_ms != 0 && role == (uint8_t)HADC_ROLE_MASTER &&
            ctx->conf.n_members >= 2 && !graceful &&
            now_ms - last_send_ms > threshold_ms) {
            hadc_warn("cluster: master heartbeat send %llu ms late (> heartbeat %u ms + "
                      "gap %u ms): real process stall, requesting demote",
                      (unsigned long long)(now_ms - last_send_ms), cadence_ms, gap_ms);
            char wake = 1;
            (void)!write(ctx->hb_selfpipe[1], &wake, 1);
        }
        last_send_ms = now_ms;
    }
}

/* Drain the self-pipe and perform the demote the heartbeat thread requested. The
 * main loop owns all role mutation, so the action runs here, not on the thread.
 * Re-checks the guard against the live state before demoting. */
void hadc_cluster_selfpipe_ready(hadc_ctx_t *ctx)
{
    char buf[64];
    while (read(ctx->hb_selfpipe[0], buf, sizeof(buf)) > 0)
        ;
    pthread_mutex_lock(&ctx->hb_lock);
    bool gactive = (ctx->graceful_restart_until_ms != 0 &&
                    realtime_ms() < ctx->graceful_restart_until_ms);
    bool fire = (ctx->role == HADC_ROLE_MASTER && ctx->conf.n_members >= 2 && !gactive);
    pthread_mutex_unlock(&ctx->hb_lock);
    if (fire) {
        hadc_info("cluster: self-monitor requested demote (main loop)");
        hadc_cluster_demote(ctx);
    }
}

int hadc_cluster_hb_start(hadc_ctx_t *ctx)
{
    if (ctx->conf.n_members == 0)
        return 0; /* standalone: no cadence */
    if (ctx->conf.cluster.heartbeat_ms == 0)
        return 0;
    if (ctx->udp_fd < 0)
        return -1;
    if (pthread_create(&ctx->hb_thread, NULL, hb_thread_main, ctx) != 0)
        return -1;
    ctx->hb_thread_started = true;
    return 0;
}


static const hadc_member_t *member_by_id(hadc_ctx_t *ctx, const char *id)
{
    for (size_t i = 0; i < ctx->conf.n_members; i++)
        if (!strcmp(ctx->conf.members[i].id, id))
            return &ctx->conf.members[i];
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
    json_t *o = json_pack("{s:s, s:b, s:s, s:s, s:s, s:s, s:o, s:I, s:I, s:I, s:I, s:s}",
                           "state", hadc_lease_state_name(l->state), "retention_active",
                           (int)l->retention_active, "address", "", "netmask", "", "gateway", "",
                           "server_id", "", "dns", dns, "t1_remaining_s",
                           (json_int_t)l->t1_remaining_s, "t2_remaining_s",
                           (json_int_t)l->t2_remaining_s, "t3_remaining_s",
                           (json_int_t)l->t3_remaining_s, "observed_at_utc",
                           (json_int_t)l->observed_at_utc, "config_hash", hex);
    if (!o) {
        json_decref(dns);
        return NULL;
    }
    put_addr(o, "address", l->address);
    put_addr(o, "netmask", l->netmask);
    put_addr(o, "gateway", l->gateway);
    put_addr(o, "server_id", l->server_id);
    if (l->gw_mac_valid) {
        char mac[2 * HADC_MAC_LEN + 1];
        for (size_t i = 0; i < HADC_MAC_LEN; i++)
            sprintf(mac + 2 * i, "%02x", l->gw_mac[i]);
        json_object_set_new(o, "gw_mac", json_string(mac));
    }
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
    if ((v = json_object_get(lj, "observed_at_utc")) && json_is_integer(v))
        out->observed_at_utc = (long long)json_integer_value(v);
    if ((v = json_object_get(lj, "config_hash")) && json_is_string(v) &&
        strlen(json_string_value(v)) == 64) {
        for (size_t i = 0; i < 32; i++) {
            unsigned b;
            if (sscanf(json_string_value(v) + 2 * i, "%2x", &b) != 1)
                break;
            out->config_hash[i] = (uint8_t)b;
        }
    }
    if ((v = json_object_get(lj, "gw_mac")) && json_is_string(v) &&
        strlen(json_string_value(v)) == 2 * HADC_MAC_LEN) {
        uint8_t mac[HADC_MAC_LEN];
        size_t i;
        for (i = 0; i < HADC_MAC_LEN; i++) {
            unsigned b;
            if (sscanf(json_string_value(v) + 2 * i, "%2x", &b) != 1)
                break;
            mac[i] = (uint8_t)b;
        }
        if (i == HADC_MAC_LEN) {
            memcpy(out->gw_mac, mac, sizeof(mac));
            out->gw_mac_valid = true;
        }
    }
}

static json_t *build_msg(hadc_ctx_t *ctx, const char *type, int with_lease)
{
    json_t *m = json_pack("{s:s, s:s, s:s, s:I, s?:s}", "type", type, "origin", ctx->conf.self,
                           "master_id", ctx->conf.designated_master, "lease_version",
                           (json_int_t)ctx->lease.version, "role", role_name(ctx->role));
    if (!m)
        return NULL;
    if (with_lease) {
        json_t *lj = lease_json(&ctx->lease);
        if (lj)
            json_object_set_new(m, "lease", lj);
    }
    /* every message carries our shared-document digest so a member can spot a
     * stale copy (plan §6) */
    json_object_set_new(m, "conf_sha256", json_string(ctx->conf.sha256));
    json_object_set_new(m, "ts_ms", json_integer((json_int_t)realtime_ms()));
    json_object_set_new(m, "graceful_restart_until_ms",
                        json_integer((json_int_t)ctx->graceful_restart_until_ms));
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
    if ((s = json_string_value(json_object_get(m, "conf_sha256"))))
        snprintf(out->conf_sha256, sizeof(out->conf_sha256), "%s", s);
    out->conf_text = json_string_value(json_object_get(m, "conf_text"));
    v = json_object_get(m, "ts_ms");
    if (v && json_is_integer(v))
        out->ts_ms = (uint64_t)json_integer_value(v);
    if ((s = json_string_value(json_object_get(m, "role"))))
        snprintf(out->role, sizeof(out->role), "%s", s);
    v = json_object_get(m, "graceful_restart_until_ms");
    if (v && json_is_integer(v))
        out->graceful_restart_until_ms = (uint64_t)json_integer_value(v);
    parse_lease(json_object_get(m, "lease"), &out->lease);
}

static void peer_touch(hadc_ctx_t *ctx, const char *id)
{
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        if (!strcmp(ctx->conf.members[i].id, id)) {
            ctx->peers[i].alive = true;
            ctx->peers[i].last_seen_ms = (uint64_t)hadc_now_ms();
            snprintf(ctx->peers[i].id, HADC_NODE_ID_MAX, "%s", id);
            ctx->peers[i].sync_address = ctx->conf.members[i].sync_address;
            ctx->n_peers = ctx->conf.n_members;
            return;
        }
    }
}

/* ---- shared-config sync (plan §6): the master's copy is authoritative ---- */

static json_t *build_conf_msg(hadc_ctx_t *ctx, const char *type, const char *sha)
{
    json_t *m = json_pack("{s:s, s:s, s:s, s:I, s:s}", "type", type, "origin", ctx->conf.self,
                           "master_id", ctx->conf.designated_master, "lease_version",
                           (json_int_t)ctx->lease.version, "conf_sha256", sha ? sha : "");
    return m;
}

/* Push our copy of the shared document to one member as bytes, so the copy the
 * receiver writes keeps its comments and formatting. */
static int send_conf_sync(hadc_ctx_t *ctx, const hadc_member_t *to)
{
    char err[256], sha[HADC_CONF_SHA_HEX];
    char *bytes = NULL;
    size_t len;

    if (!to)
        return -1;
    if (hadc_config_read_bytes(ctx->conf.base_path, HADC_CONF_MAX_BYTES, &bytes, &len, err,
                               sizeof(err)) != 0) {
        hadc_warn("conf: cannot read %s to push to %s: %s", ctx->conf.base_path, to->id, err);
        return -1;
    }
    hadc_config_sha256_bytes(bytes, len, sha);
    if (strcmp(sha, ctx->conf.sha256) != 0)
        hadc_info("conf: pushing %s as it is on disk (%s), not the loaded copy (%s)",
                  ctx->conf.base_path, sha, ctx->conf.sha256);

    json_t *m = build_conf_msg(ctx, HADC_MSG_CONF_SYNC, sha);
    if (!m) {
        free(bytes);
        return -1;
    }
    json_object_set_new(m, "conf_text", json_string(bytes));
    free(bytes);
    if (send_to_member(ctx, to, m) != 0)
        return -1;
    hadc_info("conf: conf_sync (%s) sent to %s", sha, to->id);
    return 0;
}

int hadc_cluster_push_conf(hadc_ctx_t *ctx, const char *member_id)
{
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        const hadc_member_t *m = &ctx->conf.members[i];
        if (!strcmp(m->id, ctx->conf.self))
            continue;
        if (member_id && strcmp(m->id, member_id))
            continue;
        send_conf_sync(ctx, m);
    }
    return 0;
}

/* A member accepts the document only from the master: verify the digest, write
 * it to our own copy of the shared path (atomic, verified), reload — which
 * applies it live — and ack. */
static void conf_accept(hadc_ctx_t *ctx, const hadc_msg_t *msg)
{
    char err[256], sha[HADC_CONF_SHA_HEX];
    hadc_peer_t *p = peer_entry(ctx, msg->origin);

    if (!msg->conf_text) {
        hadc_warn("conf: conf_sync from %s carried no document; ignored", msg->origin);
        return;
    }
    hadc_config_sha256_bytes(msg->conf_text, strlen(msg->conf_text), sha);
    if (!msg->conf_sha256[0] || strcmp(sha, msg->conf_sha256) != 0) {
        hadc_warn("conf: document from %s digests to %s, not the claimed %s; not written",
                  msg->origin, sha, msg->conf_sha256);
        return;
    }
    if (strcmp(sha, ctx->conf.sha256) == 0) {
        hadc_dbg("conf: document from %s matches what we already have; nothing to do",
                 msg->origin);
    } else if (hadc_config_write_text(ctx->conf.base_path, msg->conf_text, sha, err,
                                      sizeof(err)) != 0) {
        hadc_err("conf: %s", err);
        return;
    } else {
        hadc_info("conf: shared document from %s written to %s", msg->origin,
                  ctx->conf.base_path);
    }
    if (p)
        snprintf(p->conf_sha256, sizeof(p->conf_sha256), "%s", sha);
    if (strcmp(sha, ctx->conf.sha256) != 0)
        hadc_conf_reload(ctx, "conf_sync");

    json_t *ack = build_conf_msg(ctx, HADC_MSG_CONF_ACK, ctx->conf.sha256);
    send_to_member(ctx, member_by_id(ctx, msg->origin), ack);
}

/* Rebind the UDP transport after a reload changed the port or this node's
 * sync_address; 0 when nothing changed. */
int hadc_cluster_rebind(hadc_ctx_t *ctx)
{
    const hadc_member_t *self = NULL;

    for (size_t i = 0; i < ctx->conf.n_members; i++)
        if (!strcmp(ctx->conf.members[i].id, ctx->conf.self))
            self = &ctx->conf.members[i];
    if (!self) {
        if (ctx->conf.n_members == 0) {
            if (ctx->udp_fd >= 0) {
                hadc_loop_del(ctx, ctx->udp_fd);
                close(ctx->udp_fd);
                ctx->udp_fd = -1;
            }
            memset(&g_bound, 0, sizeof(g_bound));
            return 0;
        }
        hadc_warn("cluster: this node (%s) is not in the shared config members", ctx->conf.self);
        return -1;
    }
    if (ntohs(g_bound.sin_port) == ctx->conf.cluster.port &&
        memcmp(&g_bound.sin_addr, &self->sync_address, sizeof(self->sync_address)) == 0)
        return 0;

    if (ctx->udp_fd >= 0) {
        hadc_loop_del(ctx, ctx->udp_fd);
        close(ctx->udp_fd);
        ctx->udp_fd = -1;
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
        close(ctx->udp_fd);
        ctx->udp_fd = -1;
        return -1;
    }
    fcntl(ctx->udp_fd, F_SETFL, O_NONBLOCK);
    hadc_loop_add(ctx, ctx->udp_fd, udp_ready, 0);
    g_bound = addr;
    hadc_info("cluster: transport rebound to %s:%u for node %s", inet_ntoa(addr.sin_addr),
              (unsigned)ctx->conf.cluster.port, ctx->conf.self);
    return 1;
}

/* Slave pre-apply: adopt the master's lease state, apply via executor, ack. */
static void slave_adopt_and_ack(hadc_ctx_t *ctx, const hadc_msg_t *msg, int is_full)
{
    hadc_desired_t desired;
    const hadc_member_t *master = member_by_id(ctx, msg->origin);

    HB_LOCK(ctx);
    ctx->lease = msg->lease;
    ctx->lease.version = msg->lease_version;
    HB_UNLOCK(ctx);
    if (msg->ts_ms != 0) {
        uint64_t now_ms = realtime_ms();
        long long elapsed_s = now_ms > msg->ts_ms ? (long long)((now_ms - msg->ts_ms) / 1000) : 0;
        if (elapsed_s > 0)
            hadc_lease_adjust_elapsed(&ctx->lease, elapsed_s);
    }
    hadc_lease_mark_observed(&ctx->lease);
    hadc_executor_desired(ctx, &ctx->lease, &desired);
    hadc_executor_apply(ctx, &desired, hadc_lease_state_name(ctx->lease.state));
    ctx->acked_version = ctx->lease.version;
    hadc_persist_save(ctx);
    hadc_dhcpcore_write_lease_file(ctx, &ctx->lease); /* for renew-only duty */

    hadc_info("sync: %s v%llu adopted from %s; applied and acked",
              is_full ? "full_state" : "state_push",
              (unsigned long long)ctx->lease.version, msg->origin);

    json_t *ack = json_pack("{s:s, s:s, s:s, s:I, s:I}", "type", HADC_MSG_APPLY_ACK, "origin",
                             ctx->conf.self, "master_id", ctx->conf.designated_master,
                             "lease_version", (json_int_t)ctx->lease.version, "acked_version",
                             (json_int_t)ctx->acked_version);
    send_to_member(ctx, master, ack);
}

static void udp_ready(hadc_ctx_t *ctx, int fd)
{
    char buf[65536]; /* one datagram carries a whole shared document (cap 16 KiB) */
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &fromlen);
    if (n <= 0)
        return;
    buf[n] = '\0';

    hadc_msg_t msg;
    json_t *m = NULL;
    if ((uint8_t)buf[0] == 0) { /* compact binary heartbeat (JSON starts with '{') */
        if (decode_bin_heartbeat(ctx, (const uint8_t *)buf, (size_t)n, &msg) != 0) {
            hadc_warn("sync: malformed binary heartbeat from %s:%d (%zd bytes, ignored)",
                      inet_ntoa(from.sin_addr), ntohs(from.sin_port), n);
            return;
        }
    } else {
        json_error_t jerr;
        m = json_loads(buf, 0, &jerr);
        if (!m) {
            hadc_warn("sync: malformed datagram from %s:%d (ignored): %s",
                      inet_ntoa(from.sin_addr), ntohs(from.sin_port), jerr.text);
            return;
        }
        load_msg_fields(ctx, m, &msg);
    }
    int first_seen = peer_entry(ctx, msg.origin) == NULL;
    peer_touch(ctx, msg.origin);
    hadc_peer_t *p = peer_entry(ctx, msg.origin);

    /* timestamps: every message carries the sender's CLOCK_REALTIME ms; keep
     * the observed offset per peer (startup timesync + drift alarm below) */
    if (p && msg.ts_ms != 0 && strcmp(msg.origin, ctx->conf.self))
        p->clock_offset_ms = (int64_t)msg.ts_ms - (int64_t)realtime_ms();

    /* Binary heartbeats have no room for graceful_restart_until_ms; only adopt
     * from JSON messages that carry the field explicitly. */
    if (m && msg.graceful_restart_until_ms != ctx->graceful_restart_until_ms &&
        strcmp(msg.origin, ctx->conf.self)) {
        bool from_master = msg.master_id[0] && !strcmp(msg.origin, msg.master_id);
        bool from_designated = ctx->conf.designated_master[0] &&
            !strcmp(msg.origin, ctx->conf.designated_master);
        if (from_master || from_designated)
            graceful_adopt(ctx, msg.graceful_restart_until_ms, msg.origin);
    }

    if (!strcmp(msg.type, HADC_MSG_HEARTBEAT)) {
        static uint64_t last_drift_alarm_ms;
        hadc_dbg("sync: heartbeat from %s (master=%s, role=%s, version=%llu)", msg.origin,
                 msg.master_id[0] ? msg.master_id : "(none)",
                 msg.role[0] ? msg.role : "unknown", (unsigned long long)msg.lease_version);
        if (p) {
            snprintf(p->master_view, sizeof(p->master_view), "%s", msg.master_id);
            if (msg.role[0])
                snprintf(p->role_view, sizeof(p->role_view), "%s", msg.role);
        }

        /* A peer that names itself master is asserting the role. If we are the
         * master too, the higher priority (ties by id) wins; the loser demotes.
         * If we are a slave, follow the asserted master when our current one is
         * gone or has a lower priority. */
        if (strcmp(msg.origin, ctx->conf.self) && !strcmp(msg.master_id, msg.origin)) {
            const hadc_member_t *om = member_by_id(ctx, msg.origin);
            if (ctx->role == HADC_ROLE_MASTER) {
                bool peer_wins = om && (om->priority > ctx->conf.priority ||
                    (om->priority == ctx->conf.priority &&
                     strcmp(om->id, ctx->conf.self) < 0));
                if (peer_wins) {
                    hadc_warn("cluster: %s also claims master; yielding (its priority %d, "
                              "ours %d)", msg.origin, om->priority, ctx->conf.priority);
                    hadc_cluster_promote(ctx, msg.origin);
                } else {
                    hadc_info("cluster: %s also claims master; keeping the role (our priority "
                              "%d, its %d)", msg.origin, ctx->conf.priority,
                              om ? om->priority : 0);
                    propagate_role(ctx);
                }
            } else if (strcmp(msg.master_id, ctx->conf.designated_master)) {
                const hadc_member_t *cur = member_by_id(ctx, ctx->conf.designated_master);
                bool take = !master_is_alive(ctx, ctx->conf.designated_master) ||
                    (ctx->conf.cluster.preempt && om &&
                     (!cur || beats(om, cur->id, cur->priority)));
                if (om && take) {
                    snprintf(ctx->conf.designated_master, HADC_NODE_ID_MAX, "%s", om->id);
                    set_role(ctx, HADC_ROLE_SLAVE);
                    hadc_info("cluster: following master %s (was %s)", om->id,
                              cur ? cur->id : "(none)");
                    hadc_persist_save(ctx);
                }
            }
        }
        if (p && p->clock_offset_ms != 0 &&
            llabs(p->clock_offset_ms) > HADC_TIMESYNC_STEP_MS &&
            (strcmp(msg.origin, ctx->conf.designated_master) == 0 ||
             strcmp(msg.master_id, msg.origin) == 0) &&
            (uint64_t)hadc_now_ms() - last_drift_alarm_ms >=
                ctx->conf.cluster.election_deadline_ms) {
            last_drift_alarm_ms = (uint64_t)hadc_now_ms();
            hadc_warn("ALARM: master %s clock is %lld ms off ours (heartbeat ts); startup "
                      "timesync only, no runtime step",
                      msg.origin, (long long)p->clock_offset_ms);
        }
        /* Shared-config sync (plan §6): the master's copy is authoritative, so a
         * member whose digest differs asks for it, and a member that just showed
         * up gets it pushed. */
        if (ctx->role == HADC_ROLE_MASTER && strcmp(msg.origin, ctx->conf.self) && first_seen) {
            send_conf_sync(ctx, member_by_id(ctx, msg.origin));
        } else if (ctx->role == HADC_ROLE_SLAVE &&
                   !strcmp(msg.origin, ctx->conf.designated_master) &&
                   strcmp(ctx->conf.designated_master, ctx->conf.self) && msg.conf_sha256[0] &&
                   strcmp(msg.conf_sha256, ctx->conf.sha256) != 0) {
            hadc_info("conf: master's shared document is %s, ours is %s; requesting it",
                      msg.conf_sha256, ctx->conf.sha256);
            send_to_member(ctx, member_by_id(ctx, msg.origin),
                            build_conf_msg(ctx, HADC_MSG_CONF_REQ, ctx->conf.sha256));
        }
        if (ctx->role == HADC_ROLE_SLAVE && !strcmp(msg.origin, ctx->conf.designated_master) &&
            strcmp(ctx->conf.designated_master, ctx->conf.self)) {
            int gap = first_seen || msg.lease_version > ctx->lease.version + 1;
            if (gap) {
                hadc_info("sync: version gap (theirs=%llu ours=%llu%s); requesting full state",
                          (unsigned long long)msg.lease_version,
                          (unsigned long long)ctx->lease.version,
                          first_seen ? ", join" : "");
                json_t *req = json_pack("{s:s, s:s, s:s, s:I}", "type", HADC_MSG_FULL_STATE_REQ,
                                        "origin", ctx->conf.self, "master_id",
                                        ctx->conf.designated_master, "lease_version",
                                        (json_int_t)ctx->lease.version);
                send_to_member(ctx, member_by_id(ctx, msg.origin), req);
            }
        }
    } else if (!strcmp(msg.type, HADC_MSG_STATE_PUSH) || !strcmp(msg.type, HADC_MSG_FULL_STATE)) {
        if (ctx->role == HADC_ROLE_SLAVE && !strcmp(msg.origin, ctx->conf.designated_master))
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
        if (ctx->role == HADC_ROLE_MASTER && strcmp(msg.origin, ctx->conf.self)) {
            json_t *rep = build_msg(ctx, HADC_MSG_FULL_STATE, 1);
            send_to_member(ctx, member_by_id(ctx, msg.origin), rep);
            hadc_info("sync: full_state sent to %s", msg.origin);
        }
    } else if (!strcmp(msg.type, HADC_MSG_GRACEFUL)) {
        /* state adopted above */
    } else if (!strcmp(msg.type, HADC_MSG_CTL_PROMOTE)) {
        if (ctx->role == HADC_ROLE_MASTER && msg.new_master[0]) {
            hadc_info("cluster: ctl_promote from %s requests master %s", msg.origin, msg.new_master);
            hadc_cluster_promote(ctx, msg.new_master);
        } else {
            hadc_dbg("cluster: ctl_promote from %s ignored (role=%s)", msg.origin, role_name(ctx->role));
        }
    } else if (!strcmp(msg.type, HADC_MSG_ROLE_CHANGE)) {
        hadc_info("sync: role_change from %s: master is now %s", msg.origin, msg.new_master);
        if (hadc_cluster_graceful_active(ctx)) {
            hadc_info("cluster: role_change from %s ignored (graceful restart active)", msg.origin);
        } else if (msg.new_master[0]) {
            age_peers(ctx);
            const hadc_member_t *claim = member_by_id(ctx, msg.new_master);
            bool ours = !strcmp(msg.new_master, ctx->conf.self);
            bool authority = !strcmp(msg.origin, ctx->conf.designated_master);
            const hadc_member_t *winner = election_winner(ctx);

            /* Plan §4: only the election winner's announcements (or a push from
               the master we already follow) move the role; a lower-ranked
               member's self-announcement must not demote the master. Without
               preemption, an existing live master is left alone. */
            bool accept = ours || authority;

            if (!accept && claim && winner && !strcmp(winner->id, claim->id))
                accept = ctx->conf.cluster.preempt || !master_is_alive(ctx, ctx->conf.designated_master);
            if (!accept && claim && winner && !strcmp(winner->id, claim->id))
                /* During the brief post-handoff election cooldown, accept the
                   election winner (aged) even when preempt is off, so the
                   handoff converges. Any other claim is still rejected. */
                accept = (ctx->role == HADC_ROLE_SLAVE) &&
                    (uint64_t)hadc_now_ms() < g_no_elect_until_ms;

            if (!accept) {
                hadc_info("cluster: role_change from %s ignored (%s stays master)", msg.origin,
                          ctx->conf.designated_master[0] ? ctx->conf.designated_master : "(none)");
                propagate_role(ctx);
            } else {
                snprintf(ctx->conf.designated_master, HADC_NODE_ID_MAX, "%s", msg.new_master);
                set_role(ctx, ours ? HADC_ROLE_MASTER : HADC_ROLE_SLAVE);
                hadc_persist_save(ctx);
            }
        }
    } else if (!strcmp(msg.type, HADC_MSG_CONF_SYNC)) {
        if (strcmp(msg.origin, ctx->conf.self) && !strcmp(msg.origin, ctx->conf.designated_master))
            conf_accept(ctx, &msg);
        else
            hadc_info("conf: conf_sync from %s ignored (only %s is authoritative for it)",
                      msg.origin, ctx->conf.designated_master);
    } else if (!strcmp(msg.type, HADC_MSG_CONF_REQ)) {
        if (ctx->role == HADC_ROLE_MASTER && !strcmp(msg.master_id, ctx->conf.self) &&
            strcmp(msg.origin, ctx->conf.self))
            send_conf_sync(ctx, member_by_id(ctx, msg.origin));
        else
            hadc_info("conf: conf_req from %s ignored (we are not the master)", msg.origin);
    } else if (!strcmp(msg.type, HADC_MSG_CONF_ACK)) {
        hadc_peer_t *p = peer_entry(ctx, msg.origin);
        if (p)
            snprintf(p->conf_sha256, sizeof(p->conf_sha256), "%s", msg.conf_sha256);
        hadc_info("conf: %s acked shared document %s", msg.origin, msg.conf_sha256);
    } else {
        hadc_warn("sync: unknown message type '%s' from %s", msg.type, msg.origin);
    }
    if (m) /* load_msg_fields borrows strings from the parsed JSON */
        json_decref(m);
}

int hadc_cluster_init(hadc_ctx_t *ctx)
{
    g_ctx = ctx;
    g_cluster_start_ms = (uint64_t)hadc_now_ms();

    ctx->udp_fd = -1;
    memset(&g_bound, 0, sizeof(g_bound));
    if (ctx->conf.n_members == 0) {
        hadc_info("cluster: standalone mode (no members configured); heartbeat transport disabled");
        return 0;
    }

    const hadc_member_t *self = NULL;
    for (size_t i = 0; i < ctx->conf.n_members; i++)
        if (!strcmp(ctx->conf.members[i].id, ctx->conf.self))
            self = &ctx->conf.members[i];
    if (!self) {
        hadc_err("cluster: this node (%s) is not in the shared config members", ctx->conf.self);
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
        close(ctx->udp_fd);
        ctx->udp_fd = -1;
        return -1;
    }
    fcntl(ctx->udp_fd, F_SETFL, O_NONBLOCK);
    hadc_loop_add(ctx, ctx->udp_fd, udp_ready, 0);
    g_bound = addr;
    hadc_info("cluster: transport bound to %s:%u for node %s (v1 unauthenticated trusted LAN)",
              inet_ntoa(self->sync_address), (unsigned)ctx->conf.cluster.port, ctx->conf.self);
    return 0;
}

/* Age the per-member view from the heartbeat deadline. A peer that has never
 * been seen is not alive; a peer whose last heartbeat is older than the
 * deadline is not alive either. */
static void age_peers(hadc_ctx_t *ctx)
{
    uint64_t now = (uint64_t)hadc_now_ms();
    uint32_t deadline = ctx->conf.cluster.election_deadline_ms;

    if (deadline == 0)
        deadline = 6000;
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        hadc_peer_t *p = &ctx->peers[i];
        if (p->last_seen_ms == 0) {
            p->alive = false;
            continue;
        }
        p->alive = now - p->last_seen_ms <= deadline;
    }
}

static size_t alive_members(hadc_ctx_t *ctx)
{
    size_t n = 1; /* self */

    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        const hadc_member_t *m = &ctx->conf.members[i];
        if (!strcmp(m->id, ctx->conf.self))
            continue;
        if (ctx->peers[i].alive)
            n++;
    }
    return n;
}

static bool master_is_alive(hadc_ctx_t *ctx, const char *id)
{
    if (!id || !*id)
        return false;
    if (!strcmp(id, ctx->conf.self))
        return true;
    hadc_peer_t *p = peer_entry(ctx, id);
    return p && p->alive;
}

/* (priority, ties by lowest node id) ordering from plan §4: does a outrank
 * the member b_id/b_prio? */
static bool beats(const hadc_member_t *a, const char *b_id, int b_prio)
{
    return a->priority > b_prio ||
        (a->priority == b_prio && strcmp(a->id, b_id) < 0);
}

/* The member that should be master under plan §4, among the members we
 * consider live (ourself included). */
static const hadc_member_t *election_winner(hadc_ctx_t *ctx)
{
    const hadc_member_t *best = NULL;

    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        const hadc_member_t *m = &ctx->conf.members[i];
        bool live = !strcmp(m->id, ctx->conf.self);

        if (!live) {
            hadc_peer_t *p = peer_entry(ctx, m->id);
            live = p && p->alive;
        }
        if (!live)
            continue;
        if (!best || beats(m, best->id, best->priority))
            best = m;
    }
    return best;
}

/* Highest-priority live member; ties by lowest node id. */
static const hadc_member_t *best_alive(hadc_ctx_t *ctx, bool include_self)
{
    const hadc_member_t *best = NULL;

    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        const hadc_member_t *m = &ctx->conf.members[i];
        bool alive = !strcmp(m->id, ctx->conf.self) ? include_self : ctx->peers[i].alive;

        if (!alive)
            continue;
        if (!best || m->priority > best->priority ||
            (m->priority == best->priority && strcmp(m->id, best->id) < 0))
            best = m;
    }
    return best;
}

/* Built-in failover: the designated master stopped heartbeating, we have
 * quorum, and this node is the highest-priority live member. */
static void failover_check(hadc_ctx_t *ctx)
{
    static uint64_t last_alarm_ms;
    uint64_t now = (uint64_t)hadc_now_ms();
    uint32_t deadline = ctx->conf.cluster.election_deadline_ms;
    const hadc_member_t *winner;

    if (hadc_cluster_graceful_active(ctx))
        return;
    if (ctx->role != HADC_ROLE_SLAVE)
        return;
    if (ctx->conf.n_members <= 1)
        return; /* single-node bootstrap is elect_check's job */
    if (!ctx->conf.designated_master[0])
        return;
    if (!strcmp(ctx->conf.designated_master, ctx->conf.self))
        return;
    if (deadline == 0)
        deadline = 6000;
    if (now < g_no_elect_until_ms)
        return;

    hadc_peer_t *mp = peer_entry(ctx, ctx->conf.designated_master);
    bool master_dead;
    if (mp && mp->last_seen_ms != 0)
        master_dead = now - mp->last_seen_ms > deadline;
    else
        master_dead = now - g_cluster_start_ms > deadline;
    if (!master_dead)
        return;

    if (ctx->conf.cluster.quorum == HADC_QUORUM_MAJORITY &&
        alive_members(ctx) * 2 <= ctx->conf.n_members) {
        if (now - last_alarm_ms >= deadline) {
            last_alarm_ms = now;
            hadc_warn("ALARM: master %s is down but only %zu/%zu members are alive; "
                      "no quorum, not promoting",
                      ctx->conf.designated_master, alive_members(ctx),
                      ctx->conf.n_members);
        }
        return;
    }

    winner = best_alive(ctx, true);
    if (!winner || strcmp(winner->id, ctx->conf.self) != 0)
        return;

    /* Never promote into a live peer that is already asserting itself as
     * master, and only promote once every other live peer is confirmed
     * demoted (slave) so no non-slave node is left in the cluster. */
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        hadc_peer_t *p = &ctx->peers[i];
        if (!strcmp(ctx->conf.members[i].id, ctx->conf.self))
            continue;
        if (p->alive && !strcmp(p->master_view, ctx->conf.members[i].id))
            return;
        if (p->alive && strcmp(p->role_view, "slave") != 0) {
            hadc_info("cluster: failover deferred: %s not confirmed demoted (role=%s)",
                      ctx->conf.members[i].id,
                      p->role_view[0] ? p->role_view : "unknown");
            return;
        }
    }

    hadc_info("cluster: failover: master %s missed the %ums deadline; promoting self "
              "(priority %d, %zu/%zu alive)",
              ctx->conf.designated_master, deadline, ctx->conf.priority,
              alive_members(ctx), ctx->conf.n_members);
    hadc_cluster_promote(ctx, ctx->conf.self);
}

/* Preemption (cluster.preempt, plan §4): when enabled, the cluster converges
 * on the highest-priority live member: a live slave that outranks the current
 * master promotes itself. Only acts when the current master is alive and
 * asserting itself (the dead-master path is failover_check's job); the
 * ordering is a total order, so this cannot ping-pong. */
static void preempt_check(hadc_ctx_t *ctx)
{
    const hadc_member_t *self = NULL, *cur;

    if (hadc_cluster_graceful_active(ctx))
        return;
    if (ctx->role != HADC_ROLE_SLAVE)
        return;
    if ((uint64_t)hadc_now_ms() < g_no_elect_until_ms)
        return;
    if (!ctx->conf.designated_master[0] ||
        !strcmp(ctx->conf.designated_master, ctx->conf.self))
        return;
    cur = member_by_id(ctx, ctx->conf.designated_master);
    if (!cur)
        return;
    hadc_peer_t *p = peer_entry(ctx, ctx->conf.designated_master);
    if (!p || !p->alive || strcmp(p->master_view, cur->id))
        return; /* not alive-and-asserting: the election's job */
    for (size_t i = 0; i < ctx->conf.n_members; i++)
        if (!strcmp(ctx->conf.members[i].id, ctx->conf.self))
            self = &ctx->conf.members[i];
    if (!self || !beats(self, cur->id, cur->priority))
        return;
    /* Preemption demotes the current master via role propagation, but only
     * attempt it once every other live peer is already a confirmed slave. */
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        hadc_peer_t *pp = &ctx->peers[i];
        if (!strcmp(ctx->conf.members[i].id, ctx->conf.self) ||
            !strcmp(ctx->conf.members[i].id, cur->id))
            continue;
        if (pp->alive && strcmp(pp->role_view, "slave") != 0)
            return;
    }
    hadc_info("cluster: preempt: promoting self (priority %d outranks live master %s (%d))",
              self->priority, cur->id, cur->priority);
    hadc_cluster_promote(ctx, ctx->conf.self);
}

/* Heartbeat tick (called by the daemon every heartbeat_ms, all roles). */
void hadc_cluster_heartbeat(hadc_ctx_t *ctx)
{
    bool standalone = (ctx->conf.n_members == 0);

    if (ctx->graceful_restart_until_ms && !hadc_cluster_graceful_active(ctx)) {
        /* expired: persist cleared state once */
        hadc_info("cluster: graceful restart window expired");
        hadc_persist_save(ctx);
    }
    if (!standalone && hadc_cluster_graceful_active(ctx))
        hadc_cluster_broadcast_graceful(ctx);

    /* Master-side gateway MAC cache: pick up the gateway lladdr from our own
     * resolved neighbor entry (the first ARP after binding may not have
     * answered yet when the lease event fired) and push it so every member
     * holds it before a failover. */
    if (ctx->role == HADC_ROLE_MASTER && ctx->lease.gateway.s_addr != 0) {
        uint8_t mac[HADC_MAC_LEN];
        if (hadc_executor_observe_gw_mac(ctx, mac) == 0 &&
            (!ctx->lease.gw_mac_valid || !hadc_mac_equal(ctx->lease.gw_mac, mac))) {
            memcpy(ctx->lease.gw_mac, mac, sizeof(mac));
            ctx->lease.gw_mac_valid = true;
            hadc_info("cluster: gateway %s lladdr %02x:%02x:%02x:%02x:%02x:%02x cached%s",
                      inet_ntoa(ctx->lease.gateway), mac[0], mac[1], mac[2], mac[3],
                      mac[4], mac[5], standalone ? "" : "; pushing state");
            hadc_persist_save(ctx);
            if (!standalone)
                hadc_cluster_push_state(ctx, &ctx->lease);
        }
    }

    if (standalone) {
        hadc_cluster_elect_check(ctx);
        return;
    }

    /* The heartbeat send cadence and the self-monitor watchdog run on their own
     * thread (hb_thread_main), so they are never blocked by this loop's work.
     * Here we only do the main-loop maintenance that mutates shared state. */
    age_peers(ctx);
    failover_check(ctx);
    if (ctx->conf.cluster.preempt)
        preempt_check(ctx);
    hadc_cluster_elect_check(ctx);
}

/* Default-role bootstrap election: with default_role=master and no master
 * known, a node self-promotes when it is a single node, when every member is
 * alive and none is master (all slaves), or once cluster_timeout_ms has
 * elapsed (partial view: dual-master partitions still alarm). Election is by
 * priority (mirrored in the shared config), ties by lowest node id; the winner
 * announces via the normal role_change propagation path. */
void hadc_cluster_elect_check(hadc_ctx_t *ctx)
{
    bool all_alive, timeout_path;
    const char *winner;
    int wprio;

    if (hadc_cluster_graceful_active(ctx))
        return;
    if (ctx->conf.n_members == 0) {
        if (ctx->role != HADC_ROLE_MASTER)
            hadc_cluster_promote(ctx, ctx->conf.self);
        return;
    }
    if (!ctx->conf.default_role_master)
        return;
    if ((uint64_t)hadc_now_ms() < g_no_elect_until_ms)
        return;
    if (ctx->conf.designated_master[0] != '\0')
        return; /* a master is known: configured or elected */
    if (ctx->role != HADC_ROLE_SLAVE)
        return;

    all_alive = true;
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        hadc_peer_t *p;
        if (!strcmp(ctx->conf.members[i].id, ctx->conf.self))
            continue;
        p = peer_entry(ctx, ctx->conf.members[i].id);
        if (!p || !p->alive)
            all_alive = false;
    }
    timeout_path = ctx->conf.cluster.cluster_timeout_ms > 0 &&
        (uint64_t)hadc_now_ms() - g_cluster_start_ms >=
            ctx->conf.cluster.cluster_timeout_ms;
    if (!all_alive && !timeout_path)
        return;

    winner = ctx->conf.self;
    wprio = ctx->conf.priority;
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        const hadc_member_t *m = &ctx->conf.members[i];
        hadc_peer_t *p;
        if (!strcmp(m->id, ctx->conf.self))
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
    if (strcmp(winner, ctx->conf.self) != 0)
        return;

    /* Election only elects when no live peer already asserts master and every
     * live peer is confirmed demoted (slave); a live claimant is followed
     * instead and unknown/non-slave roles mean demotion is not yet confirmed. */
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        hadc_peer_t *p;
        if (!strcmp(ctx->conf.members[i].id, ctx->conf.self))
            continue;
        p = peer_entry(ctx, ctx->conf.members[i].id);
        if (p && p->alive && !strcmp(p->master_view, ctx->conf.members[i].id))
            return;
        if (p && p->alive && strcmp(p->role_view, "slave") != 0)
            return;
    }

    hadc_info("cluster: default-role election: promoting self (priority %d, %s)", wprio,
              all_alive ? "all members alive" : "cluster timeout elapsed");
    hadc_cluster_promote(ctx, ctx->conf.self);
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
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        if (!strcmp(ctx->conf.members[i].id, ctx->conf.self))
            continue;
        json_t *m = json_pack("{s:s, s:s, s:s, s:I, s:s, s:I}", "type", HADC_MSG_ROLE_CHANGE, "origin",
                              ctx->conf.self, "master_id", ctx->conf.designated_master,
                              "lease_version", (json_int_t)ctx->lease.version, "new_master",
                              ctx->conf.designated_master, "graceful_restart_until_ms",
                              (json_int_t)ctx->graceful_restart_until_ms);
        struct sockaddr_in to = { .sin_family = AF_INET,
                                  .sin_port = htons(ctx->conf.cluster.port),
                                  .sin_addr = ctx->conf.members[i].sync_address };
        if (m && send_json(ctx, &to, m) != 0)
            hadc_warn("cluster: role_change send to %s failed", ctx->conf.members[i].id);
    }
}

int hadc_cluster_startup_gate(hadc_ctx_t *ctx)
{
    char claim[HADC_NODE_ID_MAX];

    if (hadc_cluster_graceful_active(ctx))
        return 0;
    if (ctx->role != HADC_ROLE_MASTER)
        return 0;
    if (!cluster_startup_claim(ctx, claim, sizeof(claim)))
        return 0;
    const hadc_member_t *c = member_by_id(ctx, claim);
    const hadc_member_t *self = NULL;
    for (size_t i = 0; i < ctx->conf.n_members; i++)
        if (!strcmp(ctx->conf.members[i].id, ctx->conf.self))
            self = &ctx->conf.members[i];
    if (!c || !self || !beats(c, ctx->conf.self, ctx->conf.priority))
        return 0;
    snprintf(ctx->conf.designated_master, sizeof(ctx->conf.designated_master), "%s", c->id);
    set_role(ctx, HADC_ROLE_SLAVE);
    hadc_info("startup: live master %s outranks us (%d > %d); following it instead of "
              "resuming master", c->id, c->priority, ctx->conf.priority);
    return 1;
}

/* Before this node becomes master, verify every other cluster member is
 * demoted (slave) and not asserting itself as master. A peer that is not
 * currently alive cannot be asserting master; alive peers must report the
 * slave role and must not claim master in their heartbeat view. During a
 * graceful restart promotion need not wait for demotion confirmation. */
static bool cluster_all_others_demoted(hadc_ctx_t *ctx)
{
    if (hadc_cluster_graceful_active(ctx))
        return true;
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        const hadc_member_t *m = &ctx->conf.members[i];
        hadc_peer_t *p;

        if (!strcmp(m->id, ctx->conf.self))
            continue;
        p = peer_entry(ctx, m->id);
        if (!p || !p->alive)
            continue;
        if (!strcmp(p->role_view, "master") || !strcmp(p->master_view, m->id)) {
            hadc_info("cluster: cannot promote: %s is not demoted (role=%s master_view=%s)",
                      m->id, p->role_view[0] ? p->role_view : "unknown",
                      p->master_view[0] ? p->master_view : "(none)");
            return false;
        }
        if (strcmp(p->role_view, "slave") != 0) {
            hadc_info("cluster: cannot promote: %s role not confirmed slave yet (role=%s)",
                      m->id, p->role_view[0] ? p->role_view : "unknown");
            return false;
        }
    }
    return true;
}

int hadc_cluster_promote(hadc_ctx_t *ctx, const char *new_master_id)
{
    const char *target = (new_master_id && *new_master_id) ? new_master_id : ctx->conf.self;
    bool handoff = strcmp(target, ctx->conf.self) != 0;

    if (!strcmp(ctx->conf.designated_master, target) && ctx->role == (handoff ? HADC_ROLE_SLAVE : HADC_ROLE_MASTER)) {
        hadc_dbg("cluster: promote(%s) is idempotent (already master)", target);
        return 0;
    }
    if (hadc_cluster_graceful_active(ctx)) {
        hadc_info("cluster: promote(%s) refused (graceful restart active)", target);
        return -1;
    }
    /* Becoming master requires a unanimous demoted view of all other members:
     * only promote once every alive peer is confirmed slave and no peer asserts
     * master. Handoffs make this node a slave and are not a self-promotion. */
    if (!handoff && !cluster_all_others_demoted(ctx)) {
        hadc_warn("cluster: promote(%s) refused: not all cluster members are demoted slaves",
                  target);
        return -1;
    }
    snprintf(ctx->conf.designated_master, HADC_NODE_ID_MAX, "%s", target);
    set_role(ctx, handoff ? HADC_ROLE_SLAVE : HADC_ROLE_MASTER);
    if (handoff)
        /* An operator handoff to a lower-ranked member must not be immediately
           undone by this node's own preempt/election; the authority push below
           carries it cluster-wide. Failover (a dead master) is never suppressed. */
        g_no_elect_until_ms = (uint64_t)hadc_now_ms() + 60000;
    hadc_info("cluster: role change -> master=%s (this node: %s)", ctx->conf.designated_master,
              ctx->role == HADC_ROLE_MASTER ? "MASTER" : "SLAVE");
    propagate_role(ctx);
    hadc_persist_save(ctx);
    return 0;
}

int hadc_cluster_demote(hadc_ctx_t *ctx)
{
    /* A demote issued anywhere settles dual-master cluster-wide (plan §11.2).
     * When this node is the master we hand over to the best live peer; with no
     * live peer the VIP is withdrawn and election is suppressed for one
     * deadline so the operator's demote is not immediately undone. */
    if (hadc_cluster_graceful_active(ctx)) {
        hadc_info("cluster: demote refused (graceful restart active)");
        return -1;
    }
    if (ctx->role != HADC_ROLE_MASTER) {
        set_role(ctx, HADC_ROLE_SLAVE);
        hadc_info("cluster: demoted; master remains %s",
                  ctx->conf.designated_master[0] ? ctx->conf.designated_master : "(none)");
        propagate_role(ctx);
        return 0;
    }

    age_peers(ctx);
    const hadc_member_t *best = best_alive(ctx, false);
    if (best) {
        snprintf(ctx->conf.designated_master, HADC_NODE_ID_MAX, "%s", best->id);
        set_role(ctx, HADC_ROLE_SLAVE);
        hadc_info("cluster: demoted; handing the master role to %s", best->id);
    } else {
        ctx->conf.designated_master[0] = '\0';
        set_role(ctx, HADC_ROLE_SLAVE);
        g_no_elect_until_ms = (uint64_t)hadc_now_ms() +
            (ctx->conf.cluster.election_deadline_ms ? ctx->conf.cluster.election_deadline_ms
                                                    : 6000);
        hadc_info("cluster: demoted; no live peer to take over (election suppressed for "
                  "%ums)", ctx->conf.cluster.election_deadline_ms ? ctx->conf.cluster.election_deadline_ms
                                                                  : 6000);
    }
    propagate_role(ctx);
    hadc_persist_save(ctx);
    return 0;
}

int hadc_cluster_handoff(hadc_ctx_t *ctx)
{
    /* Graceful shutdown: hand the master role to the best live peer when one
     * exists. With no live peer the serving master must not withdraw service
     * (VIP/routes) — it just shuts down and stays master in state, so a
     * restart or partition heal can resume. Returns 1 if a handoff was made. */
    if (hadc_cluster_graceful_active(ctx))
        return 0;
    if (ctx->role != HADC_ROLE_MASTER)
        return 0;
    age_peers(ctx);
    const hadc_member_t *best = best_alive(ctx, false);
    if (!best)
        return 0;
    snprintf(ctx->conf.designated_master, HADC_NODE_ID_MAX, "%s", best->id);
    set_role(ctx, HADC_ROLE_SLAVE);
    hadc_info("cluster: handing the master role to %s before shutdown", best->id);
    propagate_role(ctx);
    hadc_persist_save(ctx);
    return 1;
}

int hadc_cluster_push_state(hadc_ctx_t *ctx, const hadc_lease_t *lease)
{
    if (ctx->udp_fd < 0 || ctx->role != HADC_ROLE_MASTER)
        return 0;
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        const hadc_member_t *m = &ctx->conf.members[i];
        if (!strcmp(m->id, ctx->conf.self))
            continue;
        json_t *msg = json_pack("{s:s, s:s, s:s, s:I}", "type", HADC_MSG_STATE_PUSH, "origin",
                                ctx->conf.self, "master_id", ctx->conf.designated_master,
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

/* Startup time sync (plan §4): a starting node syncs its CLOCK_REALTIME with
 * the cluster before joining. It heartbeats, listens for one window, and
 * collects each peer's wall clock from the timestamps its messages carry. The
 * current master's vote wins; otherwise the median of the observed offsets
 * decides. The clock is stepped only when the winning offset exceeds
 * HADC_TIMESYNC_STEP_MS; monotonic timers are unaffected.
 *
 * The window also records which live peers asserted themselves as master:
 * cluster_startup_claim() reports the highest-ranked one, so a node never
 * resumes the master role under a live, higher-ranked master. */
static char g_startup_claim[HADC_NODE_ID_MAX];

int cluster_startup_claim(hadc_ctx_t *ctx, char *out, size_t outsz)
{
    if (!g_startup_claim[0])
        return 0;
    const hadc_member_t *best = member_by_id(ctx, g_startup_claim);
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        const hadc_member_t *m = &ctx->conf.members[i];
        if (!strcmp(m->id, g_startup_claim) && (!best || beats(m, best->id, best->priority)))
            best = m;
    }
    if (!best)
        return 0;
    snprintf(out, outsz, "%s", best->id);
    return 1;
}

int hadc_cluster_timesync(hadc_ctx_t *ctx)
{
    struct {
        char id[HADC_NODE_ID_MAX];
        int64_t offset_ms;
        bool claims_master;
        uint64_t seen_ms;
    } seen[HADC_MEMBERS_MAX];
    size_t n_seen = 0;

    size_t others = 0;
    for (size_t i = 0; i < ctx->conf.n_members; i++)
        if (strcmp(ctx->conf.members[i].id, ctx->conf.self))
            others++;
    if (ctx->udp_fd < 0 || others == 0)
        return 0;

    uint64_t window = 3 * ctx->conf.cluster.heartbeat_ms;
    if (window < 1000)
        window = 1000;
    if (window > 10000)
        window = 10000;

    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        const hadc_member_t *m = &ctx->conf.members[i];
        uint8_t hb[HADC_WIRE_HB_LEN];
        if (!strcmp(m->id, ctx->conf.self))
            continue;
        build_bin_heartbeat(ctx, hb);
        struct sockaddr_in to = { .sin_family = AF_INET,
                                   .sin_port = htons(ctx->conf.cluster.port),
                                   .sin_addr = m->sync_address };
        send_bytes(ctx, &to, hb, sizeof(hb));
    }

    hadc_info("timesync: listening %llums for cluster clocks", (unsigned long long)window);
    uint64_t deadline = (uint64_t)hadc_now_ms() + window;
    while ((uint64_t)hadc_now_ms() < deadline) {
        struct pollfd pfd = { .fd = ctx->udp_fd, .events = POLLIN };
        int pr = poll(&pfd, 1, (int)(deadline - (uint64_t)hadc_now_ms()));
        if (pr <= 0)
            break;
        char buf[65536];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(ctx->udp_fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from,
                             &fromlen);
        if (n <= 0)
            continue;
        buf[n] = '\0';
        hadc_msg_t msg;
        json_t *m = NULL;
        if ((uint8_t)buf[0] == 0) { /* compact binary heartbeat */
            if (decode_bin_heartbeat(ctx, (const uint8_t *)buf, (size_t)n, &msg) != 0)
                continue;
        } else {
            json_error_t jerr;
            m = json_loads(buf, 0, &jerr);
            if (!m)
                continue;
            load_msg_fields(ctx, m, &msg);
        }
        char mtype[64];
        snprintf(mtype, sizeof(mtype), "%s", msg.type ? msg.type : "");
        if (m)
            json_decref(m);
        if (strcmp(mtype, HADC_MSG_HEARTBEAT) || !msg.ts_ms ||
            !strcmp(msg.origin, ctx->conf.self))
            continue;
        if ((int64_t)msg.ts_ms < HADC_TIMESYNC_MIN_MS) {
            hadc_dbg("timesync: %s clock (%llu ms) predates the sanity floor, vote "
                     "ignored", msg.origin, (unsigned long long)msg.ts_ms);
            continue;
        }
        int64_t offset = (int64_t)msg.ts_ms - (int64_t)realtime_ms();
        size_t j = 0;
        for (; j < n_seen; j++)
            if (!strcmp(seen[j].id, msg.origin))
                break;
        if (j == n_seen && n_seen < HADC_MEMBERS_MAX)
            n_seen++;
        if (j == n_seen)
            continue;
        snprintf(seen[j].id, sizeof(seen[j].id), "%s", msg.origin);
        seen[j].offset_ms = offset;
        seen[j].claims_master = !strcmp(msg.master_id, msg.origin);
        seen[j].seen_ms = (uint64_t)hadc_now_ms();
    }

    /* Record live master claims seen during the window (startup gate). */
    for (size_t j = 0; j < n_seen; j++)
        if (seen[j].claims_master && !g_startup_claim[0])
            snprintf(g_startup_claim, sizeof(g_startup_claim), "%s", seen[j].id);

    if (n_seen == 0) {
        hadc_info("timesync: no cluster clocks seen, keeping ours");
        return 0;
    }

    /* the (recent) master's vote wins; otherwise the median of the peers */
    size_t pick = n_seen;
    for (size_t j = 0; j < n_seen; j++)
        if (seen[j].claims_master && seen[j].seen_ms > (pick == n_seen ? 0 : seen[pick].seen_ms))
            pick = j;
    int64_t offset;
    const char *from_id;
    if (pick < n_seen) {
        offset = seen[pick].offset_ms;
        from_id = seen[pick].id;
    } else {
        int64_t sorted[HADC_MEMBERS_MAX];
        for (size_t j = 0; j < n_seen; j++)
            sorted[j] = seen[j].offset_ms;
        for (size_t a = 0; a < n_seen; a++)
            for (size_t b = a + 1; b < n_seen; b++)
                if (sorted[b] < sorted[a]) {
                    int64_t t = sorted[a];
                    sorted[a] = sorted[b];
                    sorted[b] = t;
                }
        offset = sorted[n_seen / 2]; /* even counts take the upper median */
        from_id = "cluster median";
    }

    if (llabs(offset) <= HADC_TIMESYNC_STEP_MS) {
        hadc_info("timesync: clock agrees with the cluster (winning offset %lld ms from %s)",
                  (long long)offset, from_id);
        return 0;
    }

    uint64_t target = realtime_ms() + (uint64_t)offset;
    struct timespec ts = {
        .tv_sec = (time_t)(target / 1000),
        .tv_nsec = (long)(target % 1000) * 1000000,
    };
    if (clock_settime(CLOCK_REALTIME, &ts) != 0) {
        hadc_warn("timesync: clock_settime failed (%s), keeping ours", strerror(errno));
        return 0;
    }
    hadc_info("timesync: CLOCK_REALTIME stepped by %+lld ms (voted by %s)", (long long)offset,
              from_id);
    return 0;
}
