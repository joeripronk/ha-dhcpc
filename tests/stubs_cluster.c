
#include <stddef.h>
#include <stdint.h>

#include "ha-dhcpc/config.h"
#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/lease.h"
#include "ha-dhcpc/persist.h"
#include "ha-dhcpc/reload.h"
#include "ha-dhcpc/types.h"
#include "internal.h"

/* cluster.c is unit-tested in isolation: everything it calls outside its own
 * translation unit is a no-op stub here. */

int hadc_config_read_bytes(const char *path, size_t max_bytes, char **out,
                           size_t *outlen, char *err, size_t errlen)
{
    (void)path; (void)max_bytes; (void)out; (void)outlen; (void)err; (void)errlen;
    return 0;
}

int hadc_config_sha256_bytes(const void *data, size_t len,
                             char out[HADC_CONF_SHA_HEX])
{
    (void)data; (void)len; (void)out;
    return 0;
}

int hadc_config_write_text(const char *path, const char *text,
                           const char sha256[HADC_CONF_SHA_HEX], char *err,
                           size_t errlen)
{
    (void)path; (void)text; (void)sha256; (void)err; (void)errlen;
    return 0;
}

int hadc_conf_reload(hadc_ctx_t *ctx, const char *why)
{
    (void)ctx; (void)why;
    return 0;
}

void hadc_promotion_finalize_complete(hadc_ctx_t *ctx, const char *reason)
{
    (void)ctx; (void)reason;
}

int hadc_dhcpcore_write_lease_file(hadc_ctx_t *ctx, const hadc_lease_t *lease)
{
    (void)ctx; (void)lease;
    return 0;
}

int hadc_executor_apply(hadc_ctx_t *ctx, const hadc_desired_t *desired,
                        const char *reason)
{
    (void)ctx; (void)desired; (void)reason;
    return 0;
}

void hadc_executor_desired(hadc_ctx_t *ctx, const hadc_lease_t *lease,
                           hadc_desired_t *out)
{
    (void)ctx; (void)lease; (void)out;
}

int hadc_executor_observe_gw_mac(hadc_ctx_t *ctx, uint8_t mac[HADC_MAC_LEN])
{
    (void)ctx; (void)mac;
    return -1;
}



int hadc_loop_add(hadc_ctx_t *ctx, int fd, hadc_fd_cb_t cb, int events)
{
    (void)ctx; (void)fd; (void)cb; (void)events;
    return 0;
}

int hadc_loop_del(hadc_ctx_t *ctx, int fd)
{
    (void)ctx; (void)fd;
    return 0;
}

int hadc_persist_save(hadc_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

void hadc_maint_lock(void) {}
void hadc_maint_unlock(void) {}
bool hadc_maint_running(void) { return false; }

/* Recording stub: cluster_test asserts on the dead-peer LSA flush hook. */
uint32_t stub_ospf_flush_last_rid;
int stub_ospf_flush_count;

void hadc_ospf_flush_lsas_of_rid(uint32_t rid_host)
{
    stub_ospf_flush_last_rid = rid_host;
    stub_ospf_flush_count++;
}
