/* HA-DHCPC persistence (M0, frozen). Mirrors plan §3/§8.
 * Cluster view (role, last lease-state version, last acked version) as JSON,
 * fsynced, so a reboot resumes via INIT-REBOOT and a restarting node rejoins
 * with its last state. Lease files themselves stay under the DHCP engine's
 * dhclient-compatible handling. All timers persisted as remaining time.
 */
#ifndef HA_DHCPC_PERSIST_H
#define HA_DHCPC_PERSIST_H

#include "lease.h"
#include "types.h"

typedef struct hadc_ctx hadc_ctx_t;

/* State restored from disk at startup. */
typedef struct {
    bool found;                  /* false => fresh start */
    hadc_role_t role;
    char master_id[HADC_NODE_ID_MAX]; /* cluster-wide master at save time */
    uint64_t lease_version;
    uint64_t acked_version;
    hadc_lease_t lease;          /* last known good (monotonic remainders) */
    uint64_t graceful_restart_until_ms;
    uint64_t ospf_seq;               /* persisted next self-LSA sequence */
    void *ospf_lsas;                 /* json_t* array of self LSAs, owned; NULL if none */
} hadc_persist_view_t;

int hadc_persist_init(hadc_ctx_t *ctx, const char *path);
int hadc_persist_load(hadc_ctx_t *ctx, hadc_persist_view_t *out);
int hadc_persist_save(hadc_ctx_t *ctx); /* atomic rename + fsync */

#endif /* HA_DHCPC_PERSIST_H */
