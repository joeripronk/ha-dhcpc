/* HA-DHCPC configuration schema (M0, frozen). Mirrors plan §6. */
#ifndef HA_DHCPC_CONFIG_H
#define HA_DHCPC_CONFIG_H

#include "types.h"

/* /etc/ha-dhcpc/master.conf — local on every node. */
typedef struct {
    char designated_master[HADC_NODE_ID_MAX];
    uint8_t master_mac[HADC_MAC_LEN];
    hadc_member_t members[HADC_MEMBERS_MAX];
    size_t n_members;
} hadc_master_conf_t;

/* /etc/ha-dhcpc/slave.conf — local per node; priority mirrors keepalived. */
typedef struct {
    char self[HADC_NODE_ID_MAX];
    int priority;
} hadc_slave_conf_t;

/* /etc/ha-dhcpc/ha-dhcpc.yaml — daemon settings. */
typedef struct {
    char interface[HADC_IFNAME_MAX];
    struct {
        uint16_t port;               /* UDP cluster transport, shared link */
        uint32_t heartbeat_ms;
        uint32_t election_deadline_ms; /* dead-master detection, alarm-only v1 */
        hadc_quorum_mode_t quorum;     /* alarm-only v1 */
    } cluster;
    struct {
        hadc_retention_policy_t retention;
        uint64_t retention_max_duration_s; /* used when retention=max_duration */
        bool rediscover_in_retention;
        uint8_t request_options[HADC_OPTS_MAX]; /* DHCP option numbers */
        size_t n_request_options;
        uint32_t rate_limit_ms; /* min ms between DHCP sends, 0=off;
                                 * Odido NL fiber needs 10000 */
    } dhcp;
    struct {
        bool routes;
        char dns_hook[HADC_PATH_MAX];  /* empty = no hook */
        bool suppress_member_dad;
        bool arp_responder;            /* built-in, master-only */
        bool announce_gratuitous;      /* gARP/unsolicited NA on promotion */
    } apply;
    char ctl_socket[HADC_PATH_MAX];
} hadc_daemon_conf_t;

/* Loaders return 0 on success, -1 on error with err filled. */
int hadc_config_load_master(const char *path, hadc_master_conf_t *out,
                            char *err, size_t errlen);
int hadc_config_load_slave(const char *path, hadc_slave_conf_t *out,
                           char *err, size_t errlen);
int hadc_config_load_daemon(const char *path, hadc_daemon_conf_t *out,
                            char *err, size_t errlen);

#endif /* HA_DHCPC_CONFIG_H */
