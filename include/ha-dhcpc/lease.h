/* HA-DHCPC lease state (M0, frozen). Mirrors plan §5. */
#ifndef HA_DHCPC_LEASE_H
#define HA_DHCPC_LEASE_H

#include "types.h"

/* State machine states. Slaves mirror the master's; only the master drives
 * transitions; promoted masters resume directly at RENEW (renew-only duty). */
typedef enum {
    HADC_LEASE_NONE = 0,   /* no lease ever acquired */
    HADC_LEASE_INIT_SELECT,
    HADC_LEASE_INIT_REBOOT,
    HADC_LEASE_BOUND,
    HADC_LEASE_RENEW,
    HADC_LEASE_REBIND,
    HADC_LEASE_RETAINED,   /* keep last-known-good (plan §5) */
} hadc_lease_state_t;

/* The versioned, cluster-synced unit of truth. version is monotonic;
 * timers are monotonic remaining seconds, never wall-clock deadlines. */
typedef struct {
    uint64_t version;
    hadc_lease_state_t state;
    bool retention_active;

    struct in_addr address;
    struct in_addr netmask;
    struct in_addr gateway;      /* 0 = none */
    /* MAC/ARP cache for the gateway on the DHCP (internet) interface: the
     * master observes it from its own resolved neighbor entry and it syncs
     * cluster-wide, so a promoted node programs the gateway neighbor entry
     * and forwards without re-discovering the gateway. */
    uint8_t gw_mac[HADC_MAC_LEN];
    bool gw_mac_valid;
    struct in_addr server_id;    /* pinned per lease (RFC 2131) */
    struct in_addr dns[HADC_DNS_MAX];
    size_t n_dns;

    uint32_t t1_remaining_s;
    uint32_t t2_remaining_s;
    uint32_t t3_remaining_s;

    /* Wall-clock time (UTC) when these remaining-second timers were last
     * observed fresh: generated locally, adopted from a peer, or recalculated
     * from persisted state. 0 means no trustworthy observation time. */
    long long observed_at_utc;

    hadc_hash_t config_hash;     /* executor-computed */
} hadc_lease_t;

void hadc_lease_adjust_elapsed(hadc_lease_t *l, long long elapsed_s);
void hadc_lease_mark_observed(hadc_lease_t *l);
void hadc_lease_prepare_for_promotion(hadc_lease_t *l);

static inline const char *hadc_lease_state_name(hadc_lease_state_t s)
{
    switch (s) {
    case HADC_LEASE_NONE:        return "NONE";
    case HADC_LEASE_INIT_SELECT: return "INIT-SELECT";
    case HADC_LEASE_INIT_REBOOT: return "INIT-REBOOT";
    case HADC_LEASE_BOUND:       return "BOUND";
    case HADC_LEASE_RENEW:       return "RENEW";
    case HADC_LEASE_REBIND:      return "REBIND";
    case HADC_LEASE_RETAINED:    return "RETAINED";
    }
    return "?";
}

#endif /* HA_DHCPC_LEASE_H */
