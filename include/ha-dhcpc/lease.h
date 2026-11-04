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
    struct in_addr server_id;    /* pinned per lease (RFC 2131) */
    struct in_addr dns[HADC_DNS_MAX];
    size_t n_dns;

    uint32_t t1_remaining_s;
    uint32_t t2_remaining_s;
    uint32_t t3_remaining_s;

    hadc_hash_t config_hash;     /* executor-computed */
} hadc_lease_t;

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
