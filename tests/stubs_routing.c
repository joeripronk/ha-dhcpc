#include <netinet/in.h>
#include "internal.h"

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
