#include <netinet/in.h>
#include "internal.h"
#include "ha-dhcpc/cluster.h"

struct in_addr hadc_routing_backup_gateway(hadc_ctx_t *ctx)
{
    (void)ctx;
    struct in_addr none = {0};
    return none;
}

void hadc_ospf_collect_self_lsas(void *arr)
{
    (void)arr;
}

uint64_t hadc_ospf_next_seq(void)
{
    return 0;
}

int hadc_cluster_push_state(hadc_ctx_t *ctx, const hadc_lease_t *lease)
{
    (void)ctx;
    (void)lease;
    return 0;
}
