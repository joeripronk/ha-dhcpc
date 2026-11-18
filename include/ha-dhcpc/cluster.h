/* HA-DHCPC cluster protocol (M0, frozen). Mirrors plan §4.
 *
 * Transport: UDP on the shared L2 segment via distinct per-node secondary
 * addresses (sync_address). v1 is unauthenticated/unencrypted (trusted LAN).
 * Wire encoding for v1 is canonical JSON (jansson), one message per datagram;
 * the heartbeat is the one exception: a compact binary frame sized for the
 * minimum Ethernet frame (layout in src/cluster.c). Message type is the "type"
 * key. Message ids are strings, not enums, so the wire stays canonical: see
 * HADC_MSG_* below.
 */
#ifndef HA_DHCPC_CLUSTER_H
#define HA_DHCPC_CLUSTER_H

#include "config.h"
#include "lease.h"

/* Wire message types (frozen strings). */
#define HADC_MSG_HEARTBEAT          "heartbeat"          /* bidirectional, every heartbeat_ms */
#define HADC_MSG_STATE_PUSH         "state_push"         /* master -> all, on every lease change */
#define HADC_MSG_APPLY_ACK          "apply_ack"          /* slave -> master, applied version + hash */
#define HADC_MSG_FULL_STATE_REQ     "full_state_req"     /* slave -> master on join/version gap > 1 */
#define HADC_MSG_FULL_STATE         "full_state"         /* master -> slave; slave applies before ack */
#define HADC_MSG_ROLE_CHANGE        "role_change"        /* promote/demote propagated cluster-wide */
#define HADC_MSG_CTL_PROMOTE        "ctl_promote"        /* member -> master: request handover to new_master */
#define HADC_MSG_CONF_SYNC          "conf_sync"          /* master -> member: shared document (plan §6) */
#define HADC_MSG_CONF_REQ           "conf_req"           /* member -> master: our shared digest differs */
#define HADC_MSG_CONF_ACK           "conf_ack"           /* member -> master: document written + applied */
#define HADC_MSG_TAKEOVER_PREP      "takeover_prep"      /* new master -> old master (in hold): local env prepared (no GARP yet); steer via the /+1 routes and ack */
#define HADC_MSG_TAKEOVER_ACK       "takeover_ack"       /* old master (in hold) -> new master: steering routes installed (steered=false when this node cannot steer); unblocks the new master's GARP + ready announce */

/* Wire role codes for the compact binary heartbeat (the only binary message
 * type; its first byte is 0, so JSON datagrams — which always start with '{'
 * — stay unambiguous on the same socket). */
#define HADC_WIRE_ROLE_UNKNOWN      0
#define HADC_WIRE_ROLE_MASTER       1
#define HADC_WIRE_ROLE_SLAVE        2
#define HADC_WIRE_ROLE_PROMOTING    3
#define HADC_WIRE_ROLE_DEMOTING     4

/* Heartbeat payload (all JSON messages carry origin/master/version/role; the
 * binary heartbeat carries them as bytes and has no room for the digest). */
typedef struct {
    const char *type;                    /* HADC_MSG_* */
    char origin[HADC_NODE_ID_MAX];       /* sender node id — never the shared MAC */
    char master_id[HADC_NODE_ID_MAX];    /* cluster-wide agreed master */
    uint64_t lease_version;              /* monotonic lease-state version */
    hadc_lease_t lease;                  /* full on FULL_STATE; the binary heartbeat has no room */
    bool retention_flag;
    hadc_hash_t config_hash;
    /* apply-ack fields */
    uint64_t acked_version;
    /* role-change fields */
    char new_master[HADC_NODE_ID_MAX];
    /* conf-sync fields: sha256 of the shared document as bytes (plan §6). The
     * document itself travels as text on conf_sync; the digest travels on the
     * JSON messages so a member can spot a stale copy and request it (the
     * binary heartbeat has no room for it). */
    char conf_sha256[HADC_CONF_SHA_HEX];
    const char *conf_text;               /* conf_sync only; borrowed, not owned */
    uint64_t ts_ms;                      /* sender's CLOCK_REALTIME ms at send time */
    char role[16];                       /* sender's own role: master|slave|unknown */
    uint64_t graceful_restart_until_ms;  /* global no-master-switch deadline (realtime ms) */
    bool steered;                        /* takeover_ack only: the acking node has its steering routes installed */
    /* heartbeat only: sender's seen-nodes view (bit i = it heard member i,
     * including itself); seen_bits_known false when the frame carried none */
    uint64_t seen_bits;
    bool seen_bits_known;
} hadc_msg_t;

/* Per-member view held by every node (fed by heartbeats/acks). */
typedef struct {
    char id[HADC_NODE_ID_MAX];
    struct in_addr sync_address;
    uint64_t last_seen_ms;        /* monotonic; 0 = never */
    uint64_t acked_version;       /* last apply-ack version */
    hadc_hash_t acked_config_hash;
    char conf_sha256[HADC_CONF_SHA_HEX]; /* last conf-ack digest from this member */
    int64_t clock_offset_ms;      /* peer CLOCK_REALTIME - ours, last heartbeat; 0 = unobserved */
    char master_view[HADC_NODE_ID_MAX]; /* peer's master_id from its last heartbeat */
    char role_view[16];           /* peer's self-reported role from its last heartbeat */
    uint64_t seen_bits;           /* last heartbeat bitmap: bit i = sender heard member i */
    bool seen_known;              /* the bitmap was carried (legacy 16-byte frames: false) */
    bool alive;
} hadc_peer_t;

typedef struct hadc_cluster hadc_cluster_t;

typedef struct hadc_ctx hadc_ctx_t; /* defined in internal.h; owns conf+state */

/* Lifecycle: init registers the cluster with the event loop and binds the
 * UDP transport on the local node's sync_address. */
int hadc_cluster_init(hadc_ctx_t *ctx);
int hadc_cluster_step(hadc_ctx_t *ctx); /* pump transport; nonblocking */

/* Startup time sync: a starting node first syncs its CLOCK_REALTIME with the
 * cluster before joining: heartbeats carry the sender's wall clock, the
 * current master's vote wins, otherwise the median of observed peers. The
 * clock is stepped only when the winning offset exceeds the step threshold;
 * monotonic timers are unaffected. Returns 0 when done (synced, below
 * threshold, or nothing to sync with). */
int hadc_cluster_timesync(hadc_ctx_t *ctx);

/* Startup gate (call right after the timesync window): never a second master.
 * If a live peer that outranks us by (priority, id) asserted itself as master
 * during the window, follow it instead of resuming the persisted master role.
 * Returns 1 when the role was changed (before any state is applied). */
int hadc_cluster_startup_gate(hadc_ctx_t *ctx);

/* Cluster maintenance cadence (ms) for peer aging/failover/election, decoupled
 * from heartbeat send rate: bounded well below the election deadline. */
uint32_t hadc_cluster_maint_interval_ms(const hadc_ctx_t *ctx);

/* Heartbeat/maintenance tick: called from the cluster-maintenance timer on every
 * role. Heartbeat send cadence and stall watchdog run on the hb thread; this
 * performs lightweight peer aging/failover/election (heavy netlink/persist/fanout
 * work runs from periodic maintenance). */
void hadc_cluster_heartbeat(hadc_ctx_t *ctx);

/* Slow-cadence master gateway-MAC refresh (netlink observe + persist/push on
 * change) and graceful-restart keepalive/expiry; called from periodic maintenance. */
void hadc_cluster_gateway_mac_refresh(hadc_ctx_t *ctx);
void hadc_cluster_graceful_keepalive(hadc_ctx_t *ctx);

/* Role-change hook: invoked when a promote/demote/role_change actually
 * changes this node's role, after the change is applied locally. */
void hadc_cluster_set_role_hook(void (*fn)(void *arg, hadc_role_t old_role,
                                           hadc_role_t new_role), void *arg);

/* Default-role bootstrap election (called from the heartbeat tick and at
 * startup): with default_role=master and no master known, self-promote when
 * single-node, when all members are alive and none is master, or once
 * cluster_timeout_ms has elapsed. Election is by priority, ties by id. */
void hadc_cluster_elect_check(hadc_ctx_t *ctx);

/* Role change entrypoints (idempotent, cooldown-guarded, logged).
 * role_change propagates cluster-wide over the UDP control path. */
int hadc_cluster_promote(hadc_ctx_t *ctx, const char *new_master_id);
int hadc_cluster_demote(hadc_ctx_t *ctx);

/* Heartbeat send cadence + self-monitor watchdog run on a dedicated thread (see
 * cluster.c). hb_start spawns it once transport is up; selfpipe_ready drains the
 * thread->main-loop wakeup and performs the requested demote on the main loop
 * (the thread never mutates shared state). */
int hadc_cluster_hb_start(hadc_ctx_t *ctx);
void hadc_cluster_selfpipe_ready(hadc_ctx_t *ctx);
void hadc_cluster_lock(void);   /* guards the fields the heartbeat thread touches */
void hadc_cluster_unlock(void);

/* Graceful handoff for shutdown: hands the master role to the best live peer
 * when one exists and returns 1; returns 0 (and leaves service intact) when
 * there is no live peer, so a lone/partitioned node does not withdraw. */
int hadc_cluster_handoff(hadc_ctx_t *ctx);

/* Seamless takeover handshake (new-master side): signal the old master recorded
 * in takeover_from that our local environment is prepared (public IP/routing
 * verified, VIPs assigned without GARP) and ask it to steer via the /+1 routes
 * and ack. 0 = prep sent; -1 = no handshake peer (finalize immediately). */
int hadc_cluster_send_takeover_prep(hadc_ctx_t *ctx);

/* Master pushes lease state to slaves on change; slaves apply then ack. */
int hadc_cluster_push_state(hadc_ctx_t *ctx, const hadc_lease_t *lease);

/* Shared-config sync (plan §6). The master is authoritative: it pushes the
 * shared document when a member joins (first traffic from it) and whenever
 * ctl update runs on it. A member whose shared digest differs from the
 * master's asks via conf_req. A receiver verifies the digest, writes the
 * document to its own copy of the shared path (atomic overwrite), reloads and
 * acks. member_id NULL = every other member. */
int hadc_cluster_push_conf(hadc_ctx_t *ctx, const char *member_id);

/* Rebind the UDP transport to the current conf (port / this node's
 * sync_address) after a reload; 0 when nothing changed. */
int hadc_cluster_rebind(hadc_ctx_t *ctx);

/* Graceful cluster restart: suppress master switches for ~60s or until
 * cancelled, cluster-wide. */
bool hadc_cluster_graceful_active(hadc_ctx_t *ctx);
int hadc_cluster_set_graceful_restart(hadc_ctx_t *ctx, bool enable);
void hadc_cluster_broadcast_graceful(hadc_ctx_t *ctx);

#endif /* HA_DHCPC_CLUSTER_H */
