/* Conntrack sync: master-to-slave replication over TCP (plan HA-DHCPC-CONNTRACK.md).
 * IPv4-only v1, separate worker thread, binary protocol. */
#ifndef HA_DHCPC_CONNTRACK_H
#define HA_DHCPC_CONNTRACK_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "types.h"

typedef struct hadc_ctx hadc_ctx_t;

typedef enum {
    HADC_CT_HELPER_UNKNOWN = 0,
    HADC_CT_HELPER_AVAILABLE,
    HADC_CT_HELPER_UNAVAILABLE,
    HADC_CT_HELPER_DEGRADED,
} hadc_ct_helper_state_t;

typedef struct {
    bool enabled;
    bool running;
    bool originating; /* master exporting */
    bool replica;     /* slave importing/staging */
    int peer_count;
    int peers_connected;
    uint64_t tx_frames;
    uint64_t rx_frames;
    uint64_t tx_entries;
    uint64_t rx_entries;
    uint64_t applied_entries;
    uint64_t dropped_entries;
    uint64_t resync_count;
    uint64_t queue_drops;
    uint32_t shadow_entries;
    hadc_ct_helper_state_t sip_helper;
    char sip_helper_reason[64];
} hadc_ct_status_t;

int hadc_conntrack_init(hadc_ctx_t *ctx);
int hadc_conntrack_start(hadc_ctx_t *ctx);
void hadc_conntrack_stop(hadc_ctx_t *ctx);
void hadc_conntrack_shutdown(hadc_ctx_t *ctx);
void hadc_conntrack_notify_role(hadc_ctx_t *ctx, hadc_role_t old_role, hadc_role_t new_role);
void hadc_conntrack_notify_config(hadc_ctx_t *ctx);
void hadc_conntrack_notify_vip(hadc_ctx_t *ctx);
int hadc_conntrack_resync(hadc_ctx_t *ctx);
int hadc_conntrack_compare(hadc_ctx_t *ctx);
bool hadc_conntrack_compare_done(const hadc_ctx_t *ctx);
char *hadc_conntrack_compare_json(const hadc_ctx_t *ctx);
void hadc_conntrack_get_status(const hadc_ctx_t *ctx, hadc_ct_status_t *out);
char *hadc_conntrack_status_json(const hadc_ctx_t *ctx);

#endif /* HA_DHCPC_CONNTRACK_H */
