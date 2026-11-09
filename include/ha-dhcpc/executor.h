/* HA-DHCPC config executor (M0, frozen). Mirrors plan §3.
 * Declarative desired state derived from the current lease state; idempotent
 * netlink reconcile (add/remove only on delta). dhclient-script compatible
 * dispatch so existing site hooks keep working.
 */
#ifndef HA_DHCPC_EXECUTOR_H
#define HA_DHCPC_EXECUTOR_H

#include "lease.h"
#include "types.h"

/* dhclient-script compatible reasons (frozen set). */
#define HADC_REASON_BOUND   "BOUND"
#define HADC_REASON_RENEW   "RENEW"
#define HADC_REASON_REBIND  "REBIND"
#define HADC_REASON_BOOT    "BOOT"
#define HADC_REASON_REBOOT  "REBOOT"
#define HADC_REASON_EXPIRE  "EXPIRE"
#define HADC_REASON_FAIL    "FAIL"
#define HADC_REASON_RELEASE "RELEASE"
#define HADC_REASON_DEBOUND "DEBOUND"

typedef struct hadc_ctx hadc_ctx_t;

typedef struct {
    char interface[HADC_IFNAME_MAX];
    bool present;              /* false = address should be absent */
    struct in_addr address;
    unsigned prefixlen;
    struct in_addr gateway;    /* 0 = no default route */
    uint8_t gw_mac[HADC_MAC_LEN]; /* cached gateway lladdr from the lease */
    bool gw_mac_valid;         /* program the gateway neighbor entry */
    struct in_addr backup_gateway; /* apply.backup_gateway; 0 = off */
    bool backup_route;         /* install the backup default route (slave only) */
    struct in_addr dns[HADC_DNS_MAX];
    size_t n_dns;
    bool add_routes;           /* apply.routes */
    /* Virtual/shared cluster addresses, copied from the effective config.
     * Present only while this node is the master; removed again on demotion. */
    bool cluster_addrs_present;
    hadc_cluster_if_t cluster_ifaces[HADC_CLUSTER_IF_MAX];
    size_t n_cluster_ifaces;
    uint8_t link_state;        /* 0 = leave as-is, 1 = ensure up, 2 = ensure down */
    hadc_hash_t config_hash;   /* canonical desired-state digest */
} hadc_desired_t;

typedef struct hadc_executor hadc_executor_t;

int hadc_executor_init(hadc_ctx_t *ctx);

/* Build desired state from a lease (empty lease => present=false). */
void hadc_executor_desired(hadc_ctx_t *ctx, const hadc_lease_t *lease,
                           hadc_desired_t *out);

/* Idempotent reconcile: no-op when current state already matches desired;
 * never flaps, never restarts services. reason is a HADC_REASON_* string
 * passed to hooks when a change is actually applied. */
int hadc_executor_apply(hadc_ctx_t *ctx, const hadc_desired_t *desired,
                        const char *reason);

/* Bring the interface up if it is administratively down (RTM_SETLINK, no-op
 * when already up). Called on promotion: the new master must be able to
 * speak DHCP. */
int hadc_executor_link_up(const char *ifname);

/* Send gratuitous ARP for every configured cluster IPv4 address (called on
 * promotion when apply.announce_gratuitous is true). IPv4 only for now. */
int hadc_executor_announce_cluster(hadc_ctx_t *ctx);

/* Observe the gateway's hardware address from this node's neighbor table
 * (master-side cache population: only states the kernel would actually use
 * for forwarding count). 0 = learned, -1 = nothing resolved. */
int hadc_executor_observe_gw_mac(hadc_ctx_t *ctx, uint8_t mac[HADC_MAC_LEN]);

#endif /* HA_DHCPC_EXECUTOR_H */
