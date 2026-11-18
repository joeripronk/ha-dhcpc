/* Internal shared context + helpers (not a public interface). */
#ifndef HA_DHCPC_INTERNAL_H
#define HA_DHCPC_INTERNAL_H

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/config.h"
#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/lease.h"
#include "ha-dhcpc/persist.h"
#include "ha-dhcpc/types.h"

#include <linux/limits.h>
#include <pthread.h>

struct hadc_conntrack;

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
    int maintfd;    /* cluster maintenance (peer aging/failover/election), decoupled from heartbeat send */
    int periodicfd; /* 1 s maintenance ticks (audit/gwping/routing/gw-mac/graceful) */
    int core_timerfd; /* DHCP core timers (dhcpcore adapter) */
    int ctl_fd;    /* unix control socket */
    int udp_fd;    /* cluster transport, bound to local sync_address */
    bool running;
    bool shutting_down;

    /* graceful cluster restart: wall-clock ms deadline (0 = inactive). */
    uint64_t graceful_restart_until_ms;

    /* Startup restore of self-originated OSPF LSAs (persist load -> OSPF init).
     * persist_ospf_lsas is a json array [{type,id,seq,age,body_hex}]; NULL if
     * none. persist_ospf_seq is the next self-LSA sequence (0 = fresh). */
    void *persist_ospf_lsas;
    uint64_t persist_ospf_seq;

    /* ctl newip: force a fresh DISCOVER and, on success, optionally abort TCP
     * connections that were using the previous lease address. */
    bool newip_pending;
    struct in_addr newip_old_addr;

    /* Controlled handoff: old master keeps forwarding (VIPs removed, public
     * IP/route kept, nft egress off) until the new master is ready or timeout. */
    bool handoff_forward_hold;
    uint64_t handoff_hold_until_ms;
    char handoff_target[HADC_NODE_ID_MAX];

    /* Demote return-traffic steering over fabric to the new master (opt-in).
     * Requires OSPF on a non-VIP interface; invalid configs disable the
     * behavior and are reported with an error. */
    bool demote_route_via_new_master_active;
    bool demote_route_via_new_master_invalid;
    char demote_route_via_new_master_reason[128];
    /* Promotion completion deferred: do not advertise role=master/gwping until
     * dataplane+VIP announce is done (and optionally after start delay). */
    bool promotion_pending;
    uint64_t gwping_start_after_ms;

    /* Seamless takeover handshake (SEAMLESS_TAKEOVER.md, new-master side): the
     * live peer that handed master over to us (set on an accepted role_change
     * promotion from a node asserting master). When set, promotion prepares
     * locally (public IP/routing verified, VIPs assigned without GARP), sends
     * takeover_prep, and defers GARP + ready until that node acks the installed
     * /+1 steering routes or promotion_finalize_at_ms expires (then GARP
     * anyway). steering_routes_ready is the demoting-side ack basis. */
    char takeover_from[HADC_NODE_ID_MAX];
    uint64_t promotion_finalize_at_ms;
    bool steering_routes_ready;

    /* Heartbeat thread: the send cadence runs here so it is never blocked by
     * main-loop work (executor/OSPF/persist); the self-monitor watchdog measures
     * a real process stall, not loop contention. Guards the fields the thread
     * reads (role, lease.version, graceful_restart_until_ms). */
    /* VIP/cluster-interface neighbor sync (master-collected, synced to slaves).
     * vip_neigh holds the effective set: master's last snapshot or slaves' last
     * received set. Applied to VIP interfaces on promotion only. */
    hadc_vip_neigh_t *vip_neighs;
    size_t n_vip_neighs;
    size_t vip_neighs_cap;
    uint64_t vip_neigh_last_resync_ms;
    pthread_mutex_t hb_lock;
    pthread_t hb_thread;
    bool hb_thread_started;
    int hb_selfpipe[2]; /* [0] read by main loop, [1] written by thread */

    struct hadc_conntrack *conntrack;
};

/* sha256 (frozen: config_hash = sha256 of canonical desired state) */
void hadc_sha256(const void *data, size_t len, uint8_t out[32]);

bool executor_action_is_fatal(int action_rc, bool action_is_fatal);

/* Seamless-takeover VIP splits (executor.c): the two sub-prefixes at
 * prefixlen+1 covering each cluster address's CIDR subnet, used as steering
 * routes. Addresses with a host prefix (>31) or whose subnet contains the
 * steering nexthop are skipped. */
typedef struct {
	struct in_addr net;
	unsigned plen;
} vip_split_t;

#define VIP_SPLIT_MAX (2 * HADC_CLUSTER_IF_MAX * HADC_CLUSTER_ADDR_MAX)

size_t vip_splits(const hadc_desired_t *d, const struct in_addr *via,
    vip_split_t out[], size_t max);

/* Complete a deferred promotion (main.c): GARP burst, DHCP core start, ready
 * announce (role flip), gateway probe, conntrack ownership + persist. Called
 * from the takeover_ack handler and the finalize deadline. */
void hadc_promotion_finalize_complete(hadc_ctx_t *ctx, const char *reason);

/* gateway-reachability probe (ping.c): master pings the lease gateway every
 * second after a promote and fails over after 3 consecutive misses; start sends
 * the first probe at once, tick drives the cadence and reply timeout, results
 * are logged and feed the executor's master default-route failover
 * (apply.master_backup_gateway). */
void hadc_gwping_start(hadc_ctx_t *ctx);
void hadc_gwping_stop(hadc_ctx_t *ctx);
void hadc_gwping_tick(hadc_ctx_t *ctx);

/* Serialized maintenance worker (step 3): heavy/IO maintenance (fsync-heavy
 * persist, netlink-heavy executor audit/routing reconcile) runs on a dedicated
 * thread, fed by main-loop dirty/event signals, so a slow netlink dump or disk
 * sync does not delay packet/ctl handling. hadc_maint_lock serializes the
 * executor/routing/ping/persist state between the worker and the main loop;
 * take it outermost (before hb_lock/ospf_lock). */
typedef void (*hadc_maint_fn_t)(void *arg);
int  hadc_maint_start(hadc_ctx_t *ctx);
void hadc_maint_stop(void);
int  hadc_maint_post_tick(hadc_ctx_t *ctx);
int  hadc_maint_post_fn(hadc_maint_fn_t fn, void *arg);
void hadc_maint_lock(void);
void hadc_maint_unlock(void);
bool hadc_maint_running(void);

void hadc_validate_demote_route_config(hadc_ctx_t *ctx, const char *why);

/* OSPF self-LSA persistence hooks (implemented in ospf.c, called by persist.c;
 * arr is a jansson json_t* array, void* to keep this header dependency-free). */
void hadc_ospf_collect_self_lsas(void *arr);
uint64_t hadc_ospf_next_seq(void);
/* last reported verdict: failover threshold reached and not yet recovered */
bool hadc_gwping_unreachable(void);

/* event loop registration */
/* Owner cleanup cannot re-establish this fd, so drop its registration when the
 * fd reports EPOLLERR/EPOLLHUP instead of letting it spin the loop. */
#define HADC_FD_ERR_DROP 0x1
int hadc_loop_add(hadc_ctx_t *ctx, int fd, void (*cb)(hadc_ctx_t *, int), int events);
int hadc_loop_del(hadc_ctx_t *ctx, int fd);
typedef void (*hadc_fd_cb_t)(hadc_ctx_t *, int);

#endif /* HA_DHCPC_INTERNAL_H */
