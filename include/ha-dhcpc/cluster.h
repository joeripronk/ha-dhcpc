/* HA-DHCPC cluster protocol (M0, frozen). Mirrors plan §4.
 *
 * Transport: UDP on the shared L2 segment via distinct per-node secondary
 * addresses (sync_address). v1 is unauthenticated/unencrypted (trusted LAN).
 * Wire encoding for v1 is canonical JSON (jansson), one message per datagram;
 * message type is the "type" key. Message ids are strings, not enums, so the
 * wire stays canonical: see HADC_MSG_* below.
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

/* Heartbeat payload (all messages carry origin/master/version). */
typedef struct {
    const char *type;                    /* HADC_MSG_* */
    char origin[HADC_NODE_ID_MAX];       /* sender node id — never the shared MAC */
    char master_id[HADC_NODE_ID_MAX];    /* cluster-wide agreed master */
    uint64_t lease_version;              /* monotonic lease-state version */
    hadc_lease_t lease;                  /* summary on heartbeat; full on FULL_STATE */
    bool retention_flag;
    hadc_hash_t config_hash;
    /* apply-ack fields */
    uint64_t acked_version;
    /* role-change fields */
    char new_master[HADC_NODE_ID_MAX];
} hadc_msg_t;

/* Per-member view held by every node (fed by heartbeats/acks). */
typedef struct {
    char id[HADC_NODE_ID_MAX];
    struct in_addr sync_address;
    uint64_t last_seen_ms;        /* monotonic; 0 = never */
    uint64_t acked_version;       /* last apply-ack version */
    hadc_hash_t acked_config_hash;
    bool alive;
} hadc_peer_t;

typedef struct hadc_cluster hadc_cluster_t;

typedef struct hadc_ctx hadc_ctx_t; /* defined in internal.h; owns conf+state */

/* Lifecycle: init registers the cluster with the event loop and binds the
 * UDP transport on the local node's sync_address. */
int hadc_cluster_init(hadc_ctx_t *ctx);
int hadc_cluster_step(hadc_ctx_t *ctx); /* pump transport; nonblocking */

/* Role change entrypoints (idempotent, cooldown-guarded, logged).
 * role_change propagates cluster-wide over the UDP control path. */
int hadc_cluster_promote(hadc_ctx_t *ctx, const char *new_master_id);
int hadc_cluster_demote(hadc_ctx_t *ctx);

/* Master pushes lease state to slaves on change; slaves apply then ack. */
int hadc_cluster_push_state(hadc_ctx_t *ctx, const hadc_lease_t *lease);

#endif /* HA_DHCPC_CLUSTER_H */
