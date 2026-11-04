/* Internal shared context + helpers (not a public interface). */
#ifndef HA_DHCPC_INTERNAL_H
#define HA_DHCPC_INTERNAL_H

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/config.h"
#include "ha-dhcpc/lease.h"
#include "ha-dhcpc/persist.h"
#include "ha-dhcpc/types.h"

#include <linux/limits.h>

struct hadc_ctx {
    hadc_master_conf_t master;
    hadc_slave_conf_t slave;
    hadc_daemon_conf_t conf;

    /* runtime state (frozen semantics: role is runtime state, not config) */
    hadc_role_t role;
    hadc_lease_t lease; /* current lease state; slaves mirror the master's */
    uint64_t applied_hash_src; /* informational; config_hash holds the digest */
    hadc_peer_t peers[HADC_MEMBERS_MAX];
    size_t n_peers;

    char persist_path[PATH_MAX];
    char pidfile_path[PATH_MAX];

    int epfd;
    int timerfd;   /* heartbeat */
    int ctl_fd;    /* unix control socket */
    int udp_fd;    /* cluster transport, bound to local sync_address */
    bool running;
};

/* sha256 (frozen: config_hash = sha256 of canonical desired state) */
void hadc_sha256(const void *data, size_t len, uint8_t out[32]);

/* event loop registration */
int hadc_loop_add(hadc_ctx_t *ctx, int fd, void (*cb)(hadc_ctx_t *, int), int events);
typedef void (*hadc_fd_cb_t)(hadc_ctx_t *, int);

#endif /* HA_DHCPC_INTERNAL_H */
