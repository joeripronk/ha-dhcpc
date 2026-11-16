#ifndef HA_DHCPC_OSPF_H
#define HA_DHCPC_OSPF_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "ha-dhcpc/config.h"
#include "ha-dhcpc/routing.h"

typedef struct hadc_ctx hadc_ctx_t;

int hadc_ospf_init(hadc_ctx_t *ctx);
int hadc_ospf_spawn(hadc_ctx_t *ctx); /* start the OSPF thread after init */
void hadc_ospf_lock(void);   /* guards g_ospf incl. conf the thread reads */
void hadc_ospf_unlock(void);
void hadc_ospf_shutdown(hadc_ctx_t *ctx);
void hadc_ospf_tick(hadc_ctx_t *ctx);
/* Recompute self-originated LSAs from desired prefixes/default-route intent. */
void hadc_ospf_originate(hadc_ctx_t *ctx,
                         const struct in_addr *public_ip32, bool want_pub,
                         bool want_default_route,
                         const void *vip_prefixes, size_t vip_prefix_count);

/* JSON status (neighbors/LSDB) for routing status. */
struct json_t;
struct json_t *hadc_ospf_status(hadc_ctx_t *ctx);

/* Collect fabric-learned default-route candidates from LSDB (AS-external 0/0). */
size_t hadc_ospf_default_candidates(hadc_ctx_t *ctx, hadc_routing_default_candidate_t *out, size_t max);

typedef struct {
    struct in_addr prefix;
    struct in_addr mask;
    unsigned prefixlen;
    struct in_addr nexthop;
    uint32_t metric;
    uint32_t age_s;   /* effective LSA age at observation time; freshest wins
                       * when the same prefix is advertised by several LSAs */
    uint8_t lsa_type;
    char origin[HADC_ROUTING_ORIGIN_MAX];
    bool valid;
} hadc_ospf_learned_route_t;

size_t hadc_ospf_learned_routes(hadc_ctx_t *ctx, hadc_ospf_learned_route_t *out, size_t max);


#endif /* HA_DHCPC_OSPF_H */
