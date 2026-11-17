/* HA-DHCPC lease state. Mirrors plan §5. */
#ifndef HA_DHCPC_LEASE_H
#define HA_DHCPC_LEASE_H

#include <jansson.h>
#include <string.h>

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

/* The versioned, cluster-synced unit of truth. version is monotonic.
 * Timer anchors are absolute UTC seconds (time_t) when the lease was
 * obtained/refreshed: renew/rebind/expire deadlines are derived from them so
 * every node computes the same remaining time from its clock, and restarts do
 * not rely on snapshot aging.  0 means unknown/unset.  Deadlines are therefore
 * a direct function of the system clock.  The old relative fields
 * (t1_remaining_s/observed_at_utc) are no longer parsed, so a lease written by
 * a pre-anchor node parses with zero timers and forces a renew on adoption:
 * upgrade a cluster in one pass, do not roll mixed versions. */
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

    /* Absolute UTC seconds (as returned by time(2)). */
    long long obtained_at_utc;
    long long t1_at_utc; /* renew */
    long long t2_at_utc; /* rebind */
    long long t3_at_utc; /* expire */

    hadc_hash_t config_hash;     /* executor-computed */
} hadc_lease_t;

/* Compute remaining seconds to each absolute timer (clamped to >= 0). */
void hadc_lease_remaining(const hadc_lease_t *l, long long now_utc,
                          uint32_t *t1, uint32_t *t2, uint32_t *t3);
uint32_t hadc_lease_remaining_one(long long at_utc, long long now_utc);
/* On promotion, delay renew on the new master by 5s (handoff churn), clamped
 * so T1 <= T2 <= T3, without accelerating or making an expired lease active. */
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

static inline hadc_lease_state_t hadc_lease_state_from_name(const char *n)
{
    if (!n)
        return HADC_LEASE_NONE;
    if (!strcmp(n, "NONE"))         return HADC_LEASE_NONE;
    if (!strcmp(n, "INIT-SELECT"))  return HADC_LEASE_INIT_SELECT;
    if (!strcmp(n, "INIT-REBOOT"))  return HADC_LEASE_INIT_REBOOT;
    if (!strcmp(n, "BOUND"))        return HADC_LEASE_BOUND;
    if (!strcmp(n, "RENEW"))        return HADC_LEASE_RENEW;
    if (!strcmp(n, "REBIND"))       return HADC_LEASE_REBIND;
    if (!strcmp(n, "RETAINED"))     return HADC_LEASE_RETAINED;
    return HADC_LEASE_NONE;
}

json_t *hadc_lease_to_json(const hadc_lease_t *l);
void hadc_lease_from_json(json_t *lj, hadc_lease_t *out);

#endif /* HA_DHCPC_LEASE_H */
