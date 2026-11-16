/* HA-DHCPC configuration schema (M0, frozen). Mirrors plan §6.
 *
 * Two files per node, one schema:
 *   /etc/ha-dhcpc/ha-dhcpc.conf        — cluster-shared config, identical on
 *     every member. The master is authoritative: it pushes the shared document
 *     to a member when it joins, and `ctl update` (master-only) re-reads the
 *     file from disk, applies it and pushes it cluster-wide. A receiver writes
 *     the received document to its own copy of this path (atomic, digest-
 *     verified) so the cluster converges across restarts.
 *   /etc/ha-dhcpc/ha-dhcpc-local.conf  — per-node overlay, wins on conflict.
 *     `self` and `priority` are per-node here (`self` defaults to the system
 *     hostname when set in neither file); any shared key may be overridden per
 *     node (interface and default_role are the usual ones).
 *
 * The merged view is what the daemon runs; the digest below is the digest of
 * the shared document only (never of a node's merged view), so it is the value
 * that is stable cluster-wide.
 */
#ifndef HA_DHCPC_CONFIG_H
#define HA_DHCPC_CONFIG_H

#include <jansson.h>

#include "log.h"
#include "types.h"

#define HADC_CONF_SHA_HEX 65 /* sha256 hex + NUL */
#define HADC_CONF_MAX_BYTES 16384 /* shared-document file cap (plan §6 sync) */

/* Effective (merged) configuration. */
typedef struct {
    /* identity: per-node fields come from the local overlay */
    char self[HADC_NODE_ID_MAX];
    int priority; /* failover priority (higher wins) */

    /* shared cluster membership */
    char designated_master[HADC_NODE_ID_MAX]; /* runtime master (may be elected) */
    char seed_master[HADC_NODE_ID_MAX];       /* file-provided cold-start seed */
    uint8_t master_mac[HADC_MAC_LEN];
    hadc_member_t members[HADC_MEMBERS_MAX];
    size_t n_members;

    /* daemon settings */
    char interface[HADC_IFNAME_MAX];
    hadc_log_level_t loglevel; /* debug|info|warn|err, default info */
    struct {
        uint16_t port;                 /* UDP cluster transport, shared link */
        uint32_t heartbeat_ms;
        uint32_t election_deadline_ms; /* dead-master detection before failover */
        uint32_t self_demote_gap_ms;   /* master self-monitor: step down when a heartbeat
                                        * tick is late by more than heartbeat_ms + this gap
                                        * (a missed beat already means an unhealthy master,
                                        * so step down before a peer steals the role).
                                        * Measured above the cadence so a small gap can't
                                        * fire on a healthy tick. 0 = off */
        hadc_quorum_mode_t quorum;     /* majority (default) or none */
        uint32_t cluster_timeout_ms;   /* default-role bootstrap deadline, 0=off */
        bool preempt; /* true (default): the cluster converges on the
                       * highest-priority live member; false: members are only
                       * elected when no live master is present */
        bool neighbor_sync;            /* sync VIP-interface REACHABLE neighbors to
                                        * slaves and apply them on promotion */
        uint32_t neighbor_sync_resync_s; /* periodic master resync of VIP neighbors,
                                          * 0 = event-driven only */
        uint32_t neighbor_sync_max;    /* max synced VIP neighbors (snapshot cap) */
        /* Virtual/shared addresses owned by the master, keyed by interface.
         * Order and contents are part of the shared document. */
        hadc_cluster_if_t ifaces[HADC_CLUSTER_IF_MAX];
        size_t n_ifaces;
    } cluster;
    bool default_role_master;          /* adopt when no master is known (plan §4) */
    struct {
        hadc_retention_policy_t retention;
        uint64_t retention_max_duration_s; /* used when retention=max_duration */
        bool rediscover_in_retention;
        uint8_t request_options[HADC_OPTS_MAX]; /* DHCP option numbers */
        size_t n_request_options;
        uint32_t rate_limit_ms; /* min ms between DHCP sends, 0=off;
                                 * Odido NL fiber needs 10000 */
        uint32_t renew_retry_interval_s; /* retry interval after a failed
                                          * RENEW/REBIND, 0 = exponential backoff */
    } dhcp;
    struct {
        bool routes;
        struct in_addr backup_gateway; /* 0 = off; higher-metric default route
                                        * installed while this node is a slave
                                        * and removed again on promotion */
        struct in_addr master_backup_gateway; /* 0 = off; on the master this
                                               * nexthop takes over the default
                                               * route while the gateway probe is
                                               * failing or there is no lease IP
                                               * yet, and hands back when the
                                               * gateway answers again */
        char dns_hook[HADC_PATH_MAX];  /* empty = no hook */
        char ddclient[HADC_PATH_MAX];  /* empty = off; run as a one-shot when the
                                        * applied address changes (master-only) */
        bool suppress_member_dad;      /* compatibility no-op */
        bool arp_responder;            /* compatibility no-op (VIP owner answers) */
        bool announce_gratuitous;      /* gratuitous ARP on promotion */
        uint32_t announce_gratuitous_duration_ms; /* GARP burst duration on promotion */
        uint32_t handoff_hold_ms;      /* keep old master forwarding before egress block */
        bool slave_link_down;          /* legacy alias for slave_isolation=down */
        hadc_slave_isolation_t slave_isolation; /* how a slave isolates the DHCP
                                                 * interface (none/down/nft) */
        bool gateway_probe;            /* master: ping lease gateway for liveness */
        uint32_t gateway_probe_interval_ms; /* probe interval, ms */
        uint32_t gateway_probe_timeout_ms;  /* reply timeout, ms */
        uint32_t gateway_probe_fail_threshold; /* consecutive misses -> unreachable */
        uint32_t gateway_probe_start_delay_ms; /* delay first probe after promote */
        bool abort_tcp_on_newip;       /* after ctl newip obtains a lease, reset
                                        * TCP connections bound to the old address */
        bool disable_ipv6;             /* global: disable IPv6 on managed ifaces (default on) */
        bool dhcp_disable_ipv6_set;    /* override for the DHCP interface */
        bool dhcp_disable_ipv6;
    } apply;
    struct {
        bool enabled;
        struct {
            enum { HADC_ADV_PUB_OFF = 0, HADC_ADV_PUB_MASTER = 1, HADC_ADV_PUB_ALWAYS = 2 } public_ip32;
            bool vip_subnets;
            enum { HADC_ADV_DEF_OFF = 0, HADC_ADV_DEF_MASTER = 1, HADC_ADV_DEF_ALWAYS = 2 } default_route; /* publish 0.0.0.0/0 */
        } advertise;
        struct {
            bool default_route; /* accept fabric 0.0.0.0/0 as backup path only */
        } accept;
        char backend[16]; /* local (default), stub */
    } routing;
    struct {
        char interfaces[HADC_CLUSTER_IF_MAX][HADC_IFNAME_MAX];
        size_t n_interfaces;
        char router_id[INET_ADDRSTRLEN]; /* 0/empty = self cluster/sync address */
        int grace_period_s; /* hold self LSAs (no rebuild/flush) this long after
                             * startup; 0 = today's behavior */
        struct {
            int type; /* 0 none, 1 plaintext, 2 md5 */
            char key[128];
            int key_id;
        } auth;
    } ospf;
    struct {
        bool enabled;
        uint16_t port;                 /* TCP conntrack replication port */
        uint32_t max_queue_entries;
        bool snapshot_on_connect;
        uint32_t resync_interval_s;
        uint32_t timer_sync_interval_s; /* master: batch non-state-changing timer updates */
        struct {
            bool non_local_only;
            bool include_related;
            bool exclude_loopback;
        } filter;
        struct {
            enum { HADC_CT_SIP_AUTO = 0, HADC_CT_SIP_REQUIRE = 1, HADC_CT_SIP_OFF = 2 } sip;
            uint32_t cache_refresh_s;
        } helpers;
        struct {
            enum { HADC_CT_APPLY_STAGED = 0, HADC_CT_APPLY_IMMEDIATE = 1 } slave_apply;
            uint32_t max_entry_age_s;
        } apply;
    } conntrack_sync;
    char ctl_socket[HADC_PATH_MAX];
    /* Engine lease DB (the dhclient-compatible lease file the core reads at
     * start and the daemon keeps current on slaves). Relative names resolve
     * against the directory of the shared config file (/etc/ha-dhcpc/ in a
     * normal install); absolute names are used as given; none/off/no/~ opts out
     * of the file entirely (resolved to an empty string: the engine starts with
     * no stored lease, so a boot enters INIT-SELECT and a promoted node
     * re-acquires instead of renewing the synced lease — the daemon's own state
     * file stays the persistence). Unset keeps the compiled-in default,
     * /var/lib/ha-dhcpc/dhclient.leases.<interface>. */
    char lease_file[HADC_PATH_MAX];

    /* resolved source paths (kept for reload) and the sha256 of the shared
     * file's bytes; the local overlay is never part of that digest. */
    char base_path[HADC_PATH_MAX];
    char local_path[HADC_PATH_MAX];
    char sha256[HADC_CONF_SHA_HEX];
} hadc_conf_t;

/* Load base + local overlay into out (both files parsed, overlay wins).
 * Returns 0 on success, -1 with err filled. */
int hadc_config_load(const char *base_path, const char *local_path,
                     hadc_conf_t *out, char *err, size_t errlen);

/* Read one YAML file into a jansson document (NULL + err on failure). */
json_t *hadc_config_read_yaml(const char *path, char *err, size_t errlen);

/* Read a file's bytes (malloc'd) — the shared document is synced as bytes so
 * a pushed copy keeps its comments and formatting. Capped by max_bytes. */
int hadc_config_read_bytes(const char *path, size_t max_bytes, char **out,
                           size_t *outlen, char *err, size_t errlen);

/* sha256 hex of a byte block. */
int hadc_config_sha256_bytes(const void *data, size_t len,
                             char out[HADC_CONF_SHA_HEX]);

/* Deep-merge overlay into base (overlay wins; objects recurse, all else is replaced).
 * Returns a new reference. */
json_t *hadc_config_merge_json(json_t *base, json_t *overlay);

/* Write text to path atomically (temp + fsync + rename) and verify by re-reading
 * it: the digest of the file on disk must match the text written. Used when the
 * master's copy of the shared document is pushed to a member (plan §6). */
int hadc_config_write_text(const char *path, const char *text,
                           const char sha256[HADC_CONF_SHA_HEX], char *err,
                           size_t errlen);

#endif /* HA_DHCPC_CONFIG_H */

