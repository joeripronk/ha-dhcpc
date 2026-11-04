/* HA-DHCPC frozen shared types (M0). See HA-DHCPC.md. */
#ifndef HA_DHCPC_TYPES_H
#define HA_DHCPC_TYPES_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HADC_NODE_ID_MAX   64
#define HADC_IFNAME_MAX    16
#define HADC_PATH_MAX      4096
#define HADC_MAC_LEN       6
#define HADC_MEMBERS_MAX   16
#define HADC_DNS_MAX       8
#define HADC_OPTS_MAX      32

typedef enum {
    HADC_ROLE_UNKNOWN = 0,
    HADC_ROLE_MASTER,
    HADC_ROLE_SLAVE,
} hadc_role_t;

typedef enum {
    HADC_RETENTION_FOREVER = 0,
    HADC_RETENTION_MAX_DURATION,
    HADC_RETENTION_UNTIL_CARRIER_LOSS,
    HADC_RETENTION_OFF,
} hadc_retention_policy_t;

typedef enum {
    HADC_QUORUM_MAJORITY = 0,
    HADC_QUORUM_NONE,
} hadc_quorum_mode_t;

/* sha256 of the canonical desired state; computed by the executor. */
typedef uint8_t hadc_hash_t[32];

typedef struct {
    char id[HADC_NODE_ID_MAX];
    struct in_addr sync_address; /* distinct per-node secondary addr, plan §2.2 */
} hadc_member_t;

static inline bool hadc_mac_equal(const uint8_t a[HADC_MAC_LEN], const uint8_t b[HADC_MAC_LEN])
{
    for (size_t i = 0; i < HADC_MAC_LEN; i++)
        if (a[i] != b[i])
            return false;
    return true;
}

#endif /* HA_DHCPC_TYPES_H */
