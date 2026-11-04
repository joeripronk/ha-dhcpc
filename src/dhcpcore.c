/* DHCP engine boundary (plan §3). M1 scaffold: stub over the vendored
 * FreeBSD dhclient fork (not vendored yet). Master-only by contract. */
#define _GNU_SOURCE

#include <stdio.h>

#include "ha-dhcpc/dhcpcore.h"
#include "ha-dhcpc/log.h"
#include "internal.h"

static const hadc_dhcp_callbacks_t *g_cb;
static void *g_cbarg;

int hadc_dhcpcore_init(hadc_ctx_t *ctx, const hadc_dhcp_callbacks_t *cb, void *arg)
{
    g_cb = cb;
    g_cbarg = arg;
    hadc_info("dhcpcore: stub ready (vendored FreeBSD dhclient fork lands in M1)");
    (void)ctx;
    return 0;
}

int hadc_dhcpcore_start(hadc_ctx_t *ctx)
{
    if (ctx->role != HADC_ROLE_MASTER) {
        hadc_dbg("dhcpcore: not started (slaves are passive to DHCP)");
        return 0;
    }
    (void)g_cb;
    (void)g_cbarg;
    hadc_dbg("dhcpcore: master-only engine would start here");
    return 0;
}

int hadc_dhcpcore_stop(hadc_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

int hadc_dhcpcore_step(hadc_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}
