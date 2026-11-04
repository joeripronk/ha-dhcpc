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
 *     `self` and `priority` are per-node here; any shared key may be overridden
 *     per node (interface and default_role are the usual ones).
 *
 * The merged view is what the daemon runs; the digest below is the digest of
 * the shared document only (never of a node's merged view), so it is the value
 * that is stable cluster-wide.
 */
#ifndef HA_DHCPC_CONFIG_H
#define HA_DHCPC_CONFIG_H

#include <jansson.h>

#include "types.h"

#define HADC_CONF_SHA_HEX 65 /* sha256 hex + NUL */
#define HADC_CONF_MAX_BYTES 16384 /* shared-document file cap (plan §6 sync) */

/* Effective (merged) configuration. */
typedef struct {
    /* identity: per-node fields come from the local overlay */
    char self[HADC_NODE_ID_MAX];
    int priority; /* mirrors this node's keepalived priority */

    /* shared cluster membership */
    char designated_master[HADC_NODE_ID_MAX];
    uint8_t master_mac[HADC_MAC_LEN];
    hadc_member_t members[HADC_MEMBERS_MAX];
    size_t n_members;

    /* daemon settings */
    char interface[HADC_IFNAME_MAX];
    struct {
        uint16_t port;                 /* UDP cluster transport, shared link */
        uint32_t heartbeat_ms;
        uint32_t election_deadline_ms; /* dead-master detection, alarm-only v1 */
        hadc_quorum_mode_t quorum;     /* alarm-only v1 */
        uint32_t cluster_timeout_ms;   /* default-role bootstrap deadline, 0=off */
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
        char dns_hook[HADC_PATH_MAX];  /* empty = no hook */
        char ddclient[HADC_PATH_MAX];  /* empty = off; run as a one-shot when the
                                        * applied address changes (master-only) */
        bool suppress_member_dad;
        bool arp_responder;            /* built-in, master-only */
        bool announce_gratuitous;      /* gARP/unsolicited NA on promotion */
    } apply;
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

