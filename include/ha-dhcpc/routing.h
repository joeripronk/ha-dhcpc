#ifndef HA_DHCPC_ROUTING_H
#define HA_DHCPC_ROUTING_H

#include <jansson.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>

#include "types.h"

#define HADC_ROUTING_MAX_CANDIDATES 32
#define HADC_ROUTING_ORIGIN_MAX 64

/* Attribution of a fabric-learned default route (0.0.0.0/0). */
typedef enum {
    HADC_ROUTE_SCOPE_UNKNOWN = 0,
    HADC_ROUTE_SCOPE_LOCAL_MASTER,  /* originated by local cluster member master only */
    HADC_ROUTE_SCOPE_REMOTE_MASTER, /* originated by a remote cluster master */
} hadc_route_scope_t;

typedef struct {
    struct in_addr gateway; /* nexthop/backup candidate; 0.0.0.0 = invalid */
    hadc_route_scope_t scope;
    char origin[HADC_ROUTING_ORIGIN_MAX]; /* router-id/node-id/source hint */
    uint64_t age_s;   /* effective LSA age at observation time, seconds;
                       * selection prefers the freshest (lowest) among equals */
    bool valid;
} hadc_routing_default_candidate_t;

int hadc_routing_init(hadc_ctx_t *ctx);
void hadc_routing_shutdown(hadc_ctx_t *ctx);

/* Recompute desired advertisements/accepted routes from current role/lease/health.
 * Idempotent; safe to call from role, lease, gateway-probe and periodic paths. */
void hadc_routing_reconcile(hadc_ctx_t *ctx, const char *reason);

/* Feed attributed fabric-learned default-route candidates from a backend (e.g.
 * OSPF/kernel observer). Selection is reapplied idempotently; pass count 0 to
 * clear. Candidates are not published. */
void hadc_routing_set_default_candidates(hadc_ctx_t *ctx,
                                         const hadc_routing_default_candidate_t *cands,
                                         size_t count, const char *reason);

/* Effective slave/backup default gateway candidate contributed by routing
 * (fabric-learned default route handling). Returns 0.0.0.0 when none. */
struct in_addr hadc_routing_backup_gateway(hadc_ctx_t *ctx);

/* Effective router-id used for routing/OSPF identity (defaults to self cluster IP). */
const char *hadc_routing_router_id(hadc_ctx_t *ctx);

/* JSON status facet for ctl/status. */
json_t *hadc_routing_status(hadc_ctx_t *ctx);

#endif /* HA_DHCPC_ROUTING_H */
