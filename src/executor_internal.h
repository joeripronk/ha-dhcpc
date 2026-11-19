#ifndef HA_DHCPC_EXECUTOR_INTERNAL_H
#define HA_DHCPC_EXECUTOR_INTERNAL_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>

#include "ha-dhcpc/executor.h"

bool executor_action_is_fatal(int action_rc, bool action_is_fatal);

/* Seamless-takeover VIP splits: the two sub-prefixes at prefixlen+1 covering
 * each cluster address's CIDR subnet, used as steering routes. Addresses with
 * a host prefix (>31) or whose subnet contains the steering nexthop are
 * skipped. */
typedef struct {
    struct in_addr net;
    unsigned plen;
} vip_split_t;

#define VIP_SPLIT_MAX (2 * HADC_CLUSTER_IF_MAX * HADC_CLUSTER_ADDR_MAX)

size_t vip_splits(const hadc_desired_t *d, const struct in_addr *via,
    vip_split_t out[], size_t max);

#endif /* HA_DHCPC_EXECUTOR_INTERNAL_H */
