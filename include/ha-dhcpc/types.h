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
#define HADC_CLUSTER_IF_MAX   8
#define HADC_CLUSTER_ADDR_MAX 16

typedef enum {
    HADC_ROLE_UNKNOWN = 0,
    HADC_ROLE_MASTER,
    HADC_ROLE_SLAVE,
    HADC_ROLE_PROMOTING, /* master setup in progress; not announced as master yet */
    HADC_ROLE_DEMOTING,  /* handing off; forwarding held, egress block pending */
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

typedef enum {
    HADC_SLAVE_ISO_NONE = 0,      /* slave leaves the DHCP link as-is */
    HADC_SLAVE_ISO_DOWN = 1,      /* slave administratively brings link down */
    HADC_SLAVE_ISO_NFT_EGRESS = 2,/* slave blocks all egress via nft (link up) */
} hadc_slave_isolation_t;

/* sha256 of the canonical desired state; computed by the executor. */
typedef uint8_t hadc_hash_t[32];

typedef struct {
    char id[HADC_NODE_ID_MAX];
    struct in_addr sync_address; /* distinct per-node secondary addr, plan §2.2 */
    int priority;                /* mirrors that node's local overlay; default-role election */
} hadc_member_t;

/* Cluster (virtual/shared) address: configured per interface, owned only by
 * the master. prefixlen is the CIDR prefix (e.g. 24 for 192.168.10.1/24). */
typedef struct {
    struct in_addr address;
    unsigned prefixlen;
} hadc_cluster_addr_t;

typedef struct {
    char interface[HADC_IFNAME_MAX];
    hadc_cluster_addr_t addrs[HADC_CLUSTER_ADDR_MAX];
    size_t n_addrs;
    bool ipv6_disable_set; /* interface override present */
    bool ipv6_disable;
} hadc_cluster_if_t;

static inline bool hadc_mac_equal(const uint8_t a[HADC_MAC_LEN], const uint8_t b[HADC_MAC_LEN])
{
    for (size_t i = 0; i < HADC_MAC_LEN; i++)
        if (a[i] != b[i])
            return false;
    return true;
}

#endif /* HA_DHCPC_TYPES_H */
