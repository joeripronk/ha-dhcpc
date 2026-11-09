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
    hadc_conf_t conf; /* effective merged config: shared doc + local overlay */

    /* runtime state (frozen semantics: role is runtime state, not config) */
    hadc_role_t role;
    hadc_lease_t lease; /* current lease state; slaves mirror the master's */
    uint64_t acked_version; /* last version this node confirmed applied */
    uint64_t applied_hash_src; /* informational; config_hash holds the digest */
    hadc_peer_t peers[HADC_MEMBERS_MAX];
    size_t n_peers;

    char persist_path[PATH_MAX];
    char pidfile_path[PATH_MAX];

    int epfd;
    int timerfd;   /* heartbeat */
    int core_timerfd; /* DHCP core timers (dhcpcore adapter) */
    int ctl_fd;    /* unix control socket */
    int udp_fd;    /* cluster transport, bound to local sync_address */
    bool running;
};

/* sha256 (frozen: config_hash = sha256 of canonical desired state) */
void hadc_sha256(const void *data, size_t len, uint8_t out[32]);

bool executor_action_is_fatal(int action_rc, bool action_is_fatal);

/* gateway-reachability probe (ping.c): master pings the lease gateway every
 * 10 s after a promote; start sends the first probe at once, tick drives the
 * 10 s cadence and reply timeout, results are logged and feed the executor's
 * master default-route failover (apply.master_backup_gateway). */
void hadc_gwping_start(hadc_ctx_t *ctx);
void hadc_gwping_stop(hadc_ctx_t *ctx);
void hadc_gwping_tick(hadc_ctx_t *ctx);
/* last reported verdict: a probe timeout that has not been answered yet */
bool hadc_gwping_unreachable(void);

/* event loop registration */
/* Owner cleanup cannot re-establish this fd, so drop its registration when the
 * fd reports EPOLLERR/EPOLLHUP instead of letting it spin the loop. */
#define HADC_FD_ERR_DROP 0x1
int hadc_loop_add(hadc_ctx_t *ctx, int fd, void (*cb)(hadc_ctx_t *, int), int events);
int hadc_loop_del(hadc_ctx_t *ctx, int fd);
typedef void (*hadc_fd_cb_t)(hadc_ctx_t *, int);

#endif /* HA_DHCPC_INTERNAL_H */
