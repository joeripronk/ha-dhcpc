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
void hadc_ospf_shutdown(hadc_ctx_t *ctx);
void hadc_ospf_tick(hadc_ctx_t *ctx);
/* Recompute self-originated LSAs from desired prefixes/default-route intent. */
void hadc_ospf_originate(hadc_ctx_t *ctx,
                         const struct in_addr *public_ip32, bool want_pub,
                         bool want_default_route,
                         const void *vip_prefixes, size_t vip_prefix_count);

#endif /* HA_DHCPC_OSPF_H */
