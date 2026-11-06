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
    struct in_addr dns[HADC_DNS_MAX];
    size_t n_dns;
    bool add_routes;           /* apply.routes */
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

#endif /* HA_DHCPC_EXECUTOR_H */
