/* Executor: declarative desired state + idempotent netlink reconcile (plan §3).
 * Adds/removes only on delta; addresses and routes we did not apply ourselves
 * (per-node sync secondaries) are left alone. dhclient-script compatible
 * dns_hook dispatch with the standard reasons. */

#include <arpa/inet.h>
#include <errno.h>
#include <jansson.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/route.h>
#include <netlink/route/addr.h>
#include <netlink/route/rule.h>
#include <netlink/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/ipv4.h"
#include "ha-dhcpc/log.h"
#include "ha-dhcpc/routing.h"
#include "internal.h"

static int nl_addr_add(struct nl_sock *sk, int ifindex, const struct in_addr *ip,
                       unsigned prefixlen);
static int nl_link_set_state(struct nl_sock *sk, int ifindex, bool up);
static int verify_desired(hadc_ctx_t *ctx, const hadc_desired_t *d);
static int executor_apply_locked(hadc_ctx_t *ctx, const hadc_desired_t *desired,
                                 const char *reason, bool from_drift);
static void monitor_ready(hadc_ctx_t *ctx, int fd);
static void apply_slave_nft_block(const char *ifname, bool block, const char *reason);
static void apply_demote_hold_nft(hadc_ctx_t *ctx, const hadc_desired_t *desired,
    const hadc_desired_t *prev, const char *reason);

static struct nl_sock *g_sk;

/* Drift self-heal state: the applied-set memo is a fast path, not the truth. */
static struct nl_sock *g_mon_sk;
static int g_mon_fd = -1;
static uint64_t g_mon_last_reconcile_ms;
static bool g_mon_pending; /* monitor events set this; a heartbeat tick acts on it */
static bool g_vip_neigh_pending; /* coalesce neighbor-driven VIP snapshot refresh */
static uint64_t g_last_vip_neigh_collect_ms;
static uint64_t g_last_audit_ms;
static uint64_t g_drift_reconciled;
static int g_last_verify = -1; /* -1 = unverified, 0 = matches, 1 = drift */

static void nl_cache_drop(struct nl_cache **c)
{
	if (c && *c) {
		nl_cache_put(*c);
		*c = NULL;
	}
}

static int hadc_nl_alloc_caches(struct nl_sock *sk, struct nl_cache **lcache,
    struct nl_cache **acache, struct nl_cache **rcache, struct nl_cache **ncache)
{
	if (lcache && rtnl_link_alloc_cache(sk, AF_UNSPEC, lcache) < 0)
		goto fail;
	if (acache && rtnl_addr_alloc_cache(sk, acache) < 0)
		goto fail;
	if (rcache && rtnl_route_alloc_cache(sk, AF_INET, 0, rcache) < 0)
		goto fail;
	if (ncache && rtnl_neigh_alloc_cache(sk, ncache) < 0)
		goto fail;
	return 0;
fail:
	nl_cache_drop(ncache);
	nl_cache_drop(rcache);
	nl_cache_drop(acache);
	nl_cache_drop(lcache);
	return -1;
}

bool executor_action_is_fatal(int action_rc, bool action_is_fatal)
{
	return action_is_fatal && action_rc < 0;
}

/* Metric of the slave-only backup default route: higher than the DHCP-derived
 * primary (metric 0), so it is used only when that primary is gone. */
#define HADC_BACKUP_ROUTE_METRIC 100

static void set_ipv6_disabled(const char *ifname, bool disable)
{
    char path[128], cur[8];
    FILE *f;
    const char want = disable ? '1' : '0';

    if (!ifname[0] || strpbrk(ifname, "./"))
        return;
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/disable_ipv6", ifname);
    f = fopen(path, "r");
    if (f) {
        size_t n = fread(cur, 1, sizeof(cur) - 1, f);
        cur[n] = '\0';
        fclose(f);
        if (cur[0] == want && (cur[1] == '\n' || cur[1] == '\0'))
            return;
    }
    f = fopen(path, "w");
    if (!f) {
        hadc_dbg("executor: set disable_ipv6=%c on %s: %s", want, ifname, strerror(errno));
        return;
    }
    if (fwrite(&want, 1, 1, f) == 1)
        hadc_info("executor: IPv6 %s on %s", disable ? "disabled" : "enabled", ifname);
    else
        hadc_dbg("executor: set disable_ipv6=%c on %s: %s", want, ifname, strerror(errno));
    fclose(f);
}

static bool cluster_if_disable_ipv6(const hadc_ctx_t *ctx, const char *ifname)
{
    for (size_t i = 0; i < ctx->conf.cluster.n_ifaces; i++) {
        const hadc_cluster_if_t *ci = &ctx->conf.cluster.ifaces[i];
        if (!strcmp(ci->interface, ifname))
            return ci->ipv6_disable_set ? ci->ipv6_disable : ctx->conf.apply.disable_ipv6;
    }
    return ctx->conf.apply.disable_ipv6;
}

static void set_rp_filter_value(const char *scope, const char *value)
{
    char path[128];
    FILE *f;
    if (!scope || strpbrk(scope, "./"))
        return;
    snprintf(path, sizeof(path), "/proc/sys/net/ipv4/conf/%s/rp_filter", scope);
    f = fopen(path, "w");
    if (!f) {
        hadc_dbg("executor: set rp_filter=%s on %s: %s", value, scope, strerror(errno));
        return;
    }
    if (fputs(value, f) < 0)
        hadc_dbg("executor: set rp_filter=%s on %s: %s", value, scope, strerror(errno));
    fclose(f);
}

static void apply_disable_ipv6(hadc_ctx_t *ctx)
{
    bool dhcp = ctx->conf.apply.dhcp_disable_ipv6_set ?
        ctx->conf.apply.dhcp_disable_ipv6 : ctx->conf.apply.disable_ipv6;
    set_ipv6_disabled(ctx->conf.interface, dhcp);
    for (size_t i = 0; i < ctx->conf.cluster.n_ifaces; i++) {
        const hadc_cluster_if_t *ci = &ctx->conf.cluster.ifaces[i];
        set_ipv6_disabled(ci->interface, cluster_if_disable_ipv6(ctx, ci->interface));
    }
}

static void apply_rp_filter(hadc_ctx_t *ctx)
{
    if (!ctx->conf.apply.disable_rp_filter)
        return;
    /* Disable reverse-path filtering on managed paths to allow asymmetric
     * forwarding during seamless takeover (stray WAN ingress forwarded over
     * the fabric to the new master). */
    set_rp_filter_value("all", "0");
    set_rp_filter_value("default", "0");
    if (ctx->conf.interface[0])
        set_rp_filter_value(ctx->conf.interface, "0");
    for (size_t i = 0; i < ctx->conf.cluster.n_ifaces; i++) {
        const hadc_cluster_if_t *ci = &ctx->conf.cluster.ifaces[i];
        if (ci->interface[0])
            set_rp_filter_value(ci->interface, "0");
    }
    for (size_t i = 0; i < ctx->conf.ospf.n_interfaces; i++) {
        if (ctx->conf.ospf.interfaces[i][0])
            set_rp_filter_value(ctx->conf.ospf.interfaces[i], "0");
    }
}

int hadc_executor_init(hadc_ctx_t *ctx)
{
    g_sk = nl_socket_alloc();
    if (!g_sk) {
        hadc_err("executor: nl_socket_alloc failed");
        return -1;
    }
	if (nl_connect(g_sk, NETLINK_ROUTE) != 0) {
		hadc_err("executor: netlink connect failed");
		nl_socket_free(g_sk);
		g_sk = NULL;
		return -1;
	}
	hadc_info("executor: netlink ready");
	apply_disable_ipv6(ctx);
	return 0;
}

/* Canonical desired-state text for hashing: stable field order. */
static void canonical_desired(const hadc_desired_t *d, char *out, size_t outsz)
{
    char addr[INET_ADDRSTRLEN], gw[INET_ADDRSTRLEN], backup[INET_ADDRSTRLEN];
    char via[INET_ADDRSTRLEN], sid[INET_ADDRSTRLEN], steer[INET_ADDRSTRLEN];

    hadc_ipv4_format(d->address, addr, sizeof(addr));
    hadc_ipv4_format(d->gateway, gw, sizeof(gw));
    hadc_ipv4_format(d->backup_gateway, backup, sizeof(backup));
    hadc_ipv4_format(d->default_via, via, sizeof(via));
    hadc_ipv4_format(d->server_id, sid, sizeof(sid));
    hadc_ipv4_format(d->steer_via, steer, sizeof(steer));
    json_t *o = json_pack(
        "{s:s, s:b, s:s, s:I, s:s, s:s, s:b, s:s, s:s, s:I, s:s, s:b, s:b, s:b, s:I, s:s, "
        "s:s, s:b, s:I, s:b}",
        "interface", d->interface, "present", d->present, "address", addr,
        "prefixlen", (json_int_t)d->prefixlen, "gateway", gw, "backup_gateway",
        backup, "backup_route", d->backup_route, "dns", "", "routes",
        d->add_routes ? "yes" : "no", "link_state", (json_int_t)d->link_state,
        "default_via", via, "slave_nft_block", d->slave_nft_block,
        "slave_sync_wan", d->slave_sync_wan, "slave_wan_local_via_master", d->slave_wan_local_via_master,
        "slave_wan_local_table", (json_int_t)d->slave_wan_local_table, "server_id", sid,
        "steer_via", steer, "vip_hold_suppress", d->vip_hold_suppress,
        "nat_bypass_mark", (json_int_t)d->nat_bypass_mark,
        "nat_bypass_notrack", d->nat_bypass_notrack);
    if (!o) {
        /* A failed json_pack must never hash as the empty string: make it loud. */
        snprintf(out, outsz, "UNHASHABLE");
        return;
    }
    json_t *dns = json_array();
    for (size_t i = 0; i < d->n_dns; i++) {
        char dbuf[INET_ADDRSTRLEN];
        json_array_append_new(dns, json_string(hadc_ipv4_format(d->dns[i], dbuf, sizeof(dbuf))));
    }
    json_object_set_new(o, "dns", dns);
    json_object_set_new(o, "cluster_present", json_boolean(d->cluster_addrs_present));
    json_t *cifs = json_array();
    for (size_t i = 0; i < d->n_cluster_ifaces; i++) {
        const hadc_cluster_if_t *ci = &d->cluster_ifaces[i];
        json_t *as = json_array();
        for (size_t j = 0; j < ci->n_addrs; j++) {
            char caddr[INET_ADDRSTRLEN + 8];
            char ipbuf[INET_ADDRSTRLEN];
            hadc_ipv4_format(ci->addrs[j].address, ipbuf, sizeof(ipbuf));
            snprintf(caddr, sizeof(caddr), "%s/%u", ipbuf, ci->addrs[j].prefixlen);
            json_array_append_new(as, json_string(caddr));
        }
        json_array_append_new(cifs, json_pack("{s:s, s:o}", "interface", ci->interface,
                                              "addresses", as));
    }
    json_object_set_new(o, "cluster_ifaces", cifs);
    char *txt = json_dumps(o, JSON_PRESERVE_ORDER | JSON_COMPACT);
    snprintf(out, outsz, "%s", txt ? txt : "");
    free(txt);
    json_decref(o);
}

/* Default-route nexthop: the lease gateway, or the master backup router while
 * the gateway probe is failing or there is no lease IP yet. Neighbor entries
 * keep the lease gateway (its lladdr is what the lease cached). */
static const struct in_addr *default_nexthop(const hadc_desired_t *d)
{
    return d->default_via.s_addr ? &d->default_via : &d->gateway;
}

/* True when the DHCP server-id is only reachable through the lease gateway,
 * so a /32 pin is what keeps unicast DHCPREQUESTs alive while the gateway
 * probe has moved the default route to the backup router. On-link servers and
 * the gateway itself are already covered by the connected route. */
static bool server_needs_pin(const hadc_desired_t *d)
{
    uint32_t mask;

    if (!d->present || d->server_id.s_addr == 0 || d->gateway.s_addr == 0)
        return false;
    if (d->server_id.s_addr == d->gateway.s_addr)
        return false;
    if (d->prefixlen >= 32)
        return true;
    mask = hadc_ipv4_prefix_mask(d->prefixlen).s_addr;
    return (d->server_id.s_addr & mask) != (d->address.s_addr & mask);
}


static struct in_addr demote_route_nexthop(hadc_ctx_t *ctx)
{
    struct in_addr none = {0};
    if (!ctx || !ctx->demote_route_via_new_master_active)
        return none;
    if (!(ctx->role == HADC_ROLE_DEMOTING && ctx->handoff_forward_hold))
        return none;
    if (!ctx->conf.apply.slave_sync_wan)
        return none;
    const char *target = ctx->handoff_target[0] ? ctx->handoff_target : ctx->conf.designated_master;
    if (!target || !*target)
        return none;
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        if (!strcmp(ctx->conf.members[i].id, target))
            return ctx->conf.members[i].sync_address;
    }
    return none;
}

void hadc_executor_desired(hadc_ctx_t *ctx, const hadc_lease_t *lease, hadc_desired_t *out)
{
    memset(out, 0, sizeof(*out));
    snprintf(out->interface, sizeof(out->interface), "%s", ctx->conf.interface);
    out->add_routes = ctx->conf.apply.routes;
    out->backup_gateway = ctx->conf.apply.backup_gateway;
    {
        struct in_addr rgw = hadc_routing_backup_gateway(ctx);
        if (rgw.s_addr != 0)
            out->backup_gateway = rgw;
    }
    bool master_like = (ctx->role == HADC_ROLE_MASTER || ctx->role == HADC_ROLE_PROMOTING);
    bool demote_hold = (ctx->role == HADC_ROLE_DEMOTING && ctx->handoff_forward_hold);
    struct in_addr demote_via = demote_route_nexthop(ctx);
    bool steering = demote_via.s_addr != 0;
    /* Seamless takeover: while steering is active during the demoting hold the VIPs
     * stay assigned (ARP replies for them are suppressed and no VIP-source traffic
     * leaves this node), so stray traffic can still be forwarded to the new master;
     * the VIPs are removed only when the hold completes. */
    out->cluster_addrs_present = master_like || (demote_hold && steering);
    out->n_cluster_ifaces = ctx->conf.cluster.n_ifaces;
    for (size_t i = 0; i < out->n_cluster_ifaces; i++)
        out->cluster_ifaces[i] = ctx->conf.cluster.ifaces[i];
    /* Backup default route: a slave keeps a higher-metric route so it stays
     * reachable when its synced lease has no gateway; a master never uses it.
     * Effective gateway may come from static config or fabric-learned routing. */
    out->backup_route = (ctx->role == HADC_ROLE_SLAVE) && out->backup_gateway.s_addr != 0;

    if (lease->state == HADC_LEASE_NONE) {
        out->present = false;
    } else {
        out->present = true;
        out->address = lease->address;
        out->prefixlen = hadc_ipv4_netmask_prefix(lease->netmask);
        out->gateway = lease->gateway;
        out->gw_mac_valid = lease->gw_mac_valid && lease->gateway.s_addr != 0;
        if (out->gw_mac_valid)
            memcpy(out->gw_mac, lease->gw_mac, sizeof(out->gw_mac));
        out->n_dns = lease->n_dns;
        for (size_t i = 0; i < lease->n_dns; i++)
            out->dns[i] = lease->dns[i];
        out->server_id = lease->server_id;
    }
    /* Slaves do not own the DHCP default route by default: they reach the network through
     * the master's VIP via the configured backup gateway. Optional slave_sync_wan keeps
     * the synced lease IP/default route on slaves (and still removes VIPs). */
    if (ctx->role == HADC_ROLE_SLAVE) {
        if (ctx->conf.apply.slave_sync_wan) {
            /* Keep present/gateway/dns/routes from the synced lease (like master), but no VIPs. */
            if (lease->address.s_addr == 0 || lease->state == HADC_LEASE_NONE)
                out->present = false;
        } else {
            out->gateway.s_addr = 0;
        }
    } else if (ctx->role == HADC_ROLE_DEMOTING && ctx->handoff_forward_hold &&
             lease->state != HADC_LEASE_NONE)
        out->gateway = lease->gateway;
    out->link_state = 0;
    out->slave_nft_block = false;
    if (master_like) {
        out->link_state = 1;
    } else if (ctx->role == HADC_ROLE_DEMOTING) {
        out->link_state = 1;
        out->slave_nft_block = false; /* enabled only after new master ready */
        if (lease->address.s_addr != 0 && lease->state != HADC_LEASE_NONE)
            out->present = true;
        if (ctx->handoff_forward_hold && lease->state != HADC_LEASE_NONE) {
            /* Keep public IP and default route during handoff hold; VIPs removed. */
            out->gateway = lease->gateway;
            out->add_routes = ctx->conf.apply.routes;
            out->backup_route = false;
        }
    } else if (ctx->role == HADC_ROLE_SLAVE && !ctx->shutting_down) {
        if (ctx->conf.apply.slave_sync_wan) {
            out->link_state = 1;
            out->slave_nft_block = false;
            /* With sync, don't add the old slave backup route; we want the synced default. */
        } else if (ctx->conf.apply.slave_isolation == HADC_SLAVE_ISO_DOWN) {
            out->link_state = 2;
            out->present = false;
        } else if (ctx->conf.apply.slave_isolation == HADC_SLAVE_ISO_NFT_EGRESS) {
            out->link_state = 1; /* keep interface up, block egress via nft */
            out->slave_nft_block = true;
            out->present = false;
        }
    }
    out->slave_sync_wan = ctx->conf.apply.slave_sync_wan;
    out->slave_wan_local_via_master = ctx->conf.apply.slave_wan_local_via_master;
    out->slave_wan_local_table = ctx->conf.apply.slave_wan_local_table;
    /* Master-only failover: while the gateway probe is failing or we have no
     * lease IP yet, the default route goes to the configured backup router and
     * hands back to the lease gateway as soon as the gateway answers again. */
    out->default_via.s_addr = 0;
    if (master_like &&
        ctx->conf.apply.master_backup_gateway.s_addr != 0 &&
        (hadc_gwping_unreachable() || lease->address.s_addr == 0))
        out->default_via = ctx->conf.apply.master_backup_gateway;
    /* Seamless takeover steering: additive split /1 routes via the new master's
     * fabric nexthop; the default route itself stays on the lease gateway. */
    out->steer_via = demote_via;
    out->nat_bypass_mark = steering ? ctx->conf.apply.demote_nat_bypass_mark : 0;
    out->nat_bypass_notrack = steering ? ctx->conf.apply.demote_notrack : false;
    out->vip_hold_suppress = demote_hold && steering;
    /* For slaves with sync_wan, do not add slave backup route. */
    if (ctx->role == HADC_ROLE_SLAVE && ctx->conf.apply.slave_sync_wan)
        out->backup_route = false;
    char canon[8192]; /* 8 ifaces x 16 addrs, worst-case CIDR text */
    canonical_desired(out, canon, sizeof(canon));
    hadc_sha256(canon, strlen(canon), out->config_hash);
}

static hadc_desired_t g_applied;
static bool g_applied_valid;

struct addr_match {
	int ifindex;
	const struct in_addr *ip;
	int plen; /* -1 = any prefix */
	struct rtnl_addr *found;
};

static void addr_match_cb(struct nl_object *obj, void *p)
{
	struct addr_match *m = p;
	struct rtnl_addr *a = (struct rtnl_addr *)obj;
	struct nl_addr *local = rtnl_addr_get_local(a);

	if (rtnl_addr_get_ifindex(a) != m->ifindex)
		return;
	if (!local || nl_addr_get_family(local) != AF_INET || nl_addr_get_len(local) != 4)
		return;
	if (m->plen >= 0 && (unsigned)rtnl_addr_get_prefixlen(a) != (unsigned)m->plen)
		return;
	if (memcmp(nl_addr_get_binary_addr(local), m->ip, 4) == 0)
		m->found = a;
}

static struct rtnl_addr *find_addr(struct nl_cache *cache, int ifindex,
    const struct in_addr *ip, int plen)
{
	struct addr_match m = { ifindex, ip, plen, NULL };

	nl_cache_foreach(cache, addr_match_cb, &m);
	return m.found;
}

static bool desired_has_cluster_addr(const hadc_desired_t *d, const char *ifname,
    const struct in_addr *ip, unsigned plen)
{
    for (size_t i = 0; i < d->n_cluster_ifaces; i++) {
        const hadc_cluster_if_t *ci = &d->cluster_ifaces[i];
        if (strcmp(ci->interface, ifname))
            continue;
        for (size_t j = 0; j < ci->n_addrs; j++)
            if (ci->addrs[j].address.s_addr == ip->s_addr &&
                ci->addrs[j].prefixlen == plen)
                return true;
    }
    return false;
}

/* Virtual/shared cluster addresses: the master holds them, slaves must not.
 * Reconcile the exact configured set (never other addresses on the interface),
 * so a node that was master before a crash/reboot also removes a leftover VIP
 * when it comes back as a slave. */
static void hadc_executor_apply_vip_neighs(hadc_ctx_t *ctx, const hadc_desired_t *desired,
    struct nl_cache *lcache);

static void apply_cluster_addrs(hadc_ctx_t *ctx, struct nl_cache *lcache,
    struct nl_cache *acache, const hadc_desired_t *d, const hadc_desired_t *prev,
    const char *reason)
{
    bool present = d->cluster_addrs_present;
    bool graceful = hadc_cluster_graceful_active(ctx);
    int rc;

    for (size_t i = 0; i < d->n_cluster_ifaces; i++) {
        const hadc_cluster_if_t *ci = &d->cluster_ifaces[i];
        struct rtnl_link *link = rtnl_link_get_by_name(lcache, ci->interface);
        int ifindex;

        if (!link) {
            if (ci->n_addrs)
                hadc_warn("executor: cluster interface %s not found", ci->interface);
            continue;
        }
        ifindex = rtnl_link_get_ifindex(link);
        for (size_t j = 0; j < ci->n_addrs; j++) {
            const hadc_cluster_addr_t *a = &ci->addrs[j];
            struct rtnl_addr *cur = find_addr(acache, ifindex, &a->address, -1);

            {
                char abuf[INET_ADDRSTRLEN];
                hadc_ipv4_format(a->address, abuf, sizeof(abuf));
                if (present) {
                    if (cur && (unsigned)rtnl_addr_get_prefixlen(cur) != a->prefixlen) {
                        if ((rc = rtnl_addr_delete(g_sk, cur, 0)) < 0)
                            hadc_warn("executor: replacing cluster address %s/%u on %s failed: %s",
                                abuf, (unsigned)rtnl_addr_get_prefixlen(cur), ci->interface,
                                nl_geterror(rc));
                        else
                            hadc_info("executor: replaced cluster address %s/%u on %s (reason=%s)",
                                abuf, (unsigned)rtnl_addr_get_prefixlen(cur), ci->interface, reason);
                        cur = NULL;
                    }
                    if (!cur) {
                        if ((rc = nl_addr_add(g_sk, ifindex, &a->address, a->prefixlen)) < 0)
                            hadc_warn("executor: adding cluster address %s/%u on %s failed: %s",
                                abuf, a->prefixlen, ci->interface, nl_geterror(rc));
                        else
                            hadc_info("executor: added cluster address %s/%u on %s (reason=%s)",
                                abuf, a->prefixlen, ci->interface, reason);
                    }
                } else if (cur) {
                    /* Graceful restart: keep VIPs in place across shutdown/restart. */
                    if (graceful) {
                        hadc_dbg("executor: graceful restart active; keeping cluster address %s/%u on %s",
                            abuf, a->prefixlen, ci->interface);
                    } else {
                        /* Any prefix left behind by a previous master is stale. */
                        if ((rc = rtnl_addr_delete(g_sk, cur, 0)) < 0)
                            hadc_warn("executor: removing cluster address %s/%u from %s failed: %s",
                                abuf, a->prefixlen, ci->interface, nl_geterror(rc));
                        else
                            hadc_info("executor: removed cluster address %s/%u from %s (reason=%s)",
                                abuf, a->prefixlen, ci->interface, reason);
                    }
                }
            }
        }
        rtnl_link_put(link);
    }

    if (present)
        hadc_executor_apply_vip_neighs(ctx, d, lcache);

    /* An address dropped from the shared config must not linger. */
    if (prev && !graceful) {
        for (size_t i = 0; i < prev->n_cluster_ifaces; i++) {
            const hadc_cluster_if_t *ci = &prev->cluster_ifaces[i];
            struct rtnl_link *link = rtnl_link_get_by_name(lcache, ci->interface);
            if (!link)
                continue;
            for (size_t j = 0; j < ci->n_addrs; j++) {
                const hadc_cluster_addr_t *a = &ci->addrs[j];
                struct rtnl_addr *stale;

                if (desired_has_cluster_addr(d, ci->interface, &a->address,
                                             a->prefixlen))
                    continue;
                stale = find_addr(acache, rtnl_link_get_ifindex(link), &a->address,
                                  (int)a->prefixlen);
                if (!stale)
                    continue;
                {
                    char abuf[INET_ADDRSTRLEN];
                    hadc_ipv4_format(a->address, abuf, sizeof(abuf));
                    if ((rc = rtnl_addr_delete(g_sk, stale, 0)) < 0)
                        hadc_warn("executor: removing stale cluster address %s/%u from %s "
                            "failed: %s", abuf, a->prefixlen, ci->interface, nl_geterror(rc));
                    else
                        hadc_info("executor: removed stale cluster address %s/%u from %s "
                            "(reason=%s)", abuf, a->prefixlen, ci->interface, reason);
                }
            }
            rtnl_link_put(link);
        }
    }
}

/* All default-route entries that conflict with ours (any type, any gateway). */
struct route_collect {
	struct rtnl_route *out[16];
	size_t n;
};

static void route_collect_cb(struct nl_object *obj, void *p)
{
	struct route_collect *c = p;
	struct rtnl_route *r = (struct rtnl_route *)obj;
	struct nl_addr *dst = rtnl_route_get_dst(r);
	static const struct in_addr any;

	if (c->n >= sizeof(c->out) / sizeof(c->out[0]))
		return;
	if (!dst || nl_addr_get_family(dst) != AF_INET || nl_addr_get_len(dst) != 4)
		return;
	if (nl_addr_get_prefixlen(dst) == 0 &&
	    memcmp(nl_addr_get_binary_addr(dst), &any, 4) == 0)
		c->out[c->n++] = r;
}

struct host_match {
	const struct in_addr *dst;
	const struct in_addr *gw;
	unsigned want_plen;
	struct rtnl_route *found;
};

static void host_route_match_cb(struct nl_object *obj, void *p)
{
	struct host_match *m = p;
	struct rtnl_route *r = (struct rtnl_route *)obj;
	struct nl_addr *dst = rtnl_route_get_dst(r);
	struct nl_addr *gw;
	int i;

	if (rtnl_route_get_type(r) != RTN_UNICAST)
		return;
	if (m->dst == NULL) {
		static const struct in_addr any;
		if (!dst || nl_addr_get_family(dst) != AF_INET || nl_addr_get_len(dst) != 4)
			return;
		if (nl_addr_get_prefixlen(dst) != m->want_plen ||
		    memcmp(nl_addr_get_binary_addr(dst), &any, 4) != 0)
			return;
	} else {
		uint32_t base, got;
		if (!dst || nl_addr_get_family(dst) != AF_INET || nl_addr_get_len(dst) != 4)
			return;
		if (nl_addr_get_prefixlen(dst) != m->want_plen)
			return;
		/* prefix comparison on the network address, not the raw row */
		base = ntohl(m->dst->s_addr) & hadc_ipv4_prefix_mask_host(m->want_plen);
		got = ntohl(*(const uint32_t *)nl_addr_get_binary_addr(dst)) & hadc_ipv4_prefix_mask_host(m->want_plen);
		if (got != base)
			return;
	}
	for (i = 0; i < rtnl_route_get_nnexthops(r); i++) {
		gw = rtnl_route_nh_get_gateway(rtnl_route_nexthop_n(r, i));
		if (gw && nl_addr_get_len(gw) == 4 &&
		    memcmp(nl_addr_get_binary_addr(gw), m->gw, 4) == 0) {
			m->found = r;
			return;
		}
	}
}

static struct rtnl_route *find_default(struct nl_cache *cache, const struct in_addr *gw)
{
	struct host_match m;
	memset(&m, 0, sizeof(m));
	m.gw = gw;
	nl_cache_foreach(cache, host_route_match_cb, &m);
	return m.found;
}

static struct rtnl_route *find_host_route(struct nl_cache *cache, const struct in_addr *dst,
    const struct in_addr *gw)
{
	struct host_match m;
	memset(&m, 0, sizeof(m));
	m.dst = dst;
	m.gw = gw;
	m.want_plen = 32;
	nl_cache_foreach(cache, host_route_match_cb, &m);
	return m.found;
}

static struct rtnl_route *find_prefix_route(struct nl_cache *cache, const struct in_addr *dst,
    unsigned plen, const struct in_addr *gw)
{
	struct host_match m;
	memset(&m, 0, sizeof(m));
	m.dst = dst;
	m.gw = gw;
	m.want_plen = plen;
	nl_cache_foreach(cache, host_route_match_cb, &m);
	return m.found;
}

/* Seamless-takeover VIP splits: for each cluster address with a CIDR prefix
 * (prefixlen <= 31), the two sub-prefixes at prefixlen+1 covering its subnet.
 * They beat the connected route for the subnet, so forwarded traffic for
 * addresses inside it is steered to the new master instead of being processed
 * on this node. Packets whose destination is the VIP address itself still hit
 * the kernel's /32 local route (longest prefix) and are handled by the nft
 * scoping chains. Addresses whose subnet contains the steering nexthop are
 * skipped: the route to the nexthop would resolve through the splits. */
size_t vip_splits(const hadc_desired_t *d, const struct in_addr *via,
    vip_split_t out[], size_t max)
{
	size_t n = 0;

	for (size_t i = 0; i < d->n_cluster_ifaces; i++) {
		for (size_t j = 0; j < d->cluster_ifaces[i].n_addrs; j++) {
			const hadc_cluster_addr_t *a = &d->cluster_ifaces[i].addrs[j];
			unsigned plen = a->prefixlen;
			uint32_t mask, base, half;
			vip_split_t s[2];

			if (!a->address.s_addr || plen > 31)
				continue;
			mask = hadc_ipv4_prefix_mask_host(plen);
			base = ntohl(a->address.s_addr) & mask;
			if (via->s_addr && (ntohl(via->s_addr) & mask) == base)
				continue;
			half = 1u << (32 - (plen + 1));
			s[0].net.s_addr = htonl(base);
			s[0].plen = plen + 1;
			s[1].net.s_addr = htonl(base + half);
			s[1].plen = plen + 1;
			for (size_t k = 0; k < 2 && n < max; k++) {
				bool dup = false;
				for (size_t m2 = 0; m2 < n; m2++) {
					if (out[m2].net.s_addr == s[k].net.s_addr && out[m2].plen == s[k].plen) {
						dup = true;
						break;
					}
				}
				if (!dup)
					out[n++] = s[k];
			}
		}
	}
	return n;
}

static int nl_route_del_default_table(struct nl_sock *sk, uint32_t table, const struct in_addr *gw)
{
	struct nl_msg *m = nlmsg_alloc_simple(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK);
	struct rtmsg *rt;

	if (!m)
		return -1;
	rt = (struct rtmsg *) nlmsg_reserve(m, sizeof(*rt), NLA_ALIGNTO);
	if (!rt) {
		nlmsg_free(m);
		return -1;
	}
	rt->rtm_family = AF_INET;
	rt->rtm_dst_len = 0;
	rt->rtm_src_len = 0;
	rt->rtm_tos = 0;
	if (table < 256) {
		rt->rtm_table = (unsigned char)table;
	} else {
		rt->rtm_table = RT_TABLE_UNSPEC;
	}
	rt->rtm_protocol = RTPROT_STATIC;
	rt->rtm_scope = RT_SCOPE_UNIVERSE;
	rt->rtm_type = RTN_UNICAST;
	nla_put(m, RTA_GATEWAY, 4, gw);
	if (table >= 256) {
		uint32_t t = table;
		nla_put(m, RTA_TABLE, 4, &t);
	}
	return nl_send_sync(sk, m); /* consumes m */
}

/* dhclient-script compatible hook environment. */
static void run_hook(char *const argv[], const hadc_desired_t *prev,
    const hadc_desired_t *d, const char *reason)
{
	char e_reason[96], e_if[96], e_newip[96], e_oldip[96], e_mask[96], e_gw[96];
	char e_dns[512];
	struct in_addr mask;
	char *envp[9];
	size_t n = 0, pos;
	pid_t pid;
	int status;

	{
		char abuf[INET_ADDRSTRLEN], obuf[INET_ADDRSTRLEN], mbuf[INET_ADDRSTRLEN], gbuf[INET_ADDRSTRLEN];
		mask = hadc_ipv4_prefix_mask(d->prefixlen);
		snprintf(e_reason, sizeof(e_reason), "reason=%s", reason);
		snprintf(e_if, sizeof(e_if), "interface=%s", d->interface);
		snprintf(e_newip, sizeof(e_newip), "new_ip_address=%s",
		    d->present ? hadc_ipv4_format(d->address, abuf, sizeof(abuf)) : "");
		snprintf(e_oldip, sizeof(e_oldip), "old_ip_address=%s",
		    prev && prev->present ? hadc_ipv4_format(prev->address, obuf, sizeof(obuf)) : "");
		snprintf(e_mask, sizeof(e_mask), "new_mask=%s",
		    d->present ? hadc_ipv4_format(mask, mbuf, sizeof(mbuf)) : "");
		snprintf(e_gw, sizeof(e_gw), "new_routers=%s",
		    d->gateway.s_addr ? hadc_ipv4_format(d->gateway, gbuf, sizeof(gbuf)) : "");
	}
	pos = 0;
	for (size_t i = 0; i < d->n_dns && pos < sizeof(e_dns) - 16; i++) {
		char dbuf[INET_ADDRSTRLEN];
		pos += snprintf(e_dns + pos, sizeof(e_dns) - pos, "%s%s", i ? " " : "",
		    hadc_ipv4_format(d->dns[i], dbuf, sizeof(dbuf)));
	}
	snprintf(e_dns + pos, sizeof(e_dns) - pos, "%s", pos ? "" : "new_domain_name_servers=");

	envp[n++] = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
	envp[n++] = e_reason;
	envp[n++] = e_if;
	envp[n++] = e_newip;
	envp[n++] = e_oldip;
	envp[n++] = e_mask;
	envp[n++] = e_gw;
	envp[n++] = e_dns;
	envp[n] = NULL;

	pid = fork();
	if (pid < 0) {
		hadc_warn("executor: fork for hook %s failed", argv[0]);
		return;
	}
	if (pid == 0) {
		execve(argv[0], argv, envp);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		hadc_warn("executor: hook %s (reason=%s) did not exit 0", argv[0], reason);
	else
		hadc_info("executor: hook %s done (reason=%s)", argv[0], reason);
}

/* libnl's high-level addr builder always sends prefixlen 32 for primary
   addresses, so add via a hand-built RTM_NEWADDR with the real prefix. */
static int nl_addr_add(struct nl_sock *sk, int ifindex, const struct in_addr *ip,
    unsigned plen)
{
	struct nl_msg *m = nlmsg_alloc_simple(RTM_NEWADDR,
	    NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK);
	struct ifaddrmsg *ifa;

	if (!m)
		return -1;
	ifa = (struct ifaddrmsg *) nlmsg_reserve(m, sizeof(*ifa), NLA_ALIGNTO);
	if (!ifa) {
		nlmsg_free(m);
		return -1;
	}
	ifa->ifa_family = AF_INET;
	ifa->ifa_prefixlen = (unsigned char)plen;
	ifa->ifa_flags = 0;
	ifa->ifa_scope = RT_SCOPE_UNIVERSE;
	ifa->ifa_index = (unsigned int)ifindex;
	if (plen < 32) {
		uint32_t mask = hadc_ipv4_prefix_mask_host(plen);
		struct in_addr bc;
		bc.s_addr = htonl((ntohl(ip->s_addr) & mask) | ~mask);
		nla_put(m, IFA_BROADCAST, 4, &bc);
	}
	nla_put(m, IFA_LOCAL, 4, ip);
	nla_put(m, IFA_ADDRESS, 4, ip);
	return nl_send_sync(sk, m); /* consumes m */
}

static int nl_route_add_default_table(struct nl_sock *sk, int ifindex, const struct in_addr *gw,
    uint32_t metric, uint32_t table)
{
	struct nl_msg *m = nlmsg_alloc_simple(RTM_NEWROUTE,
	    NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK);
	struct rtmsg *rt;

	if (!m)
		return -1;
	rt = (struct rtmsg *) nlmsg_reserve(m, sizeof(*rt), NLA_ALIGNTO);
	if (!rt) {
		nlmsg_free(m);
		return -1;
	}
	rt->rtm_family = AF_INET;
	rt->rtm_dst_len = 0;
	rt->rtm_src_len = 0;
	rt->rtm_tos = 0;
	if (table < 256) {
		rt->rtm_table = (unsigned char)table;
	} else {
		rt->rtm_table = RT_TABLE_UNSPEC;
	}
	rt->rtm_protocol = RTPROT_STATIC;
	rt->rtm_scope = RT_SCOPE_UNIVERSE;
	rt->rtm_type = RTN_UNICAST;
	if (ifindex)
		rt->rtm_flags = RTNH_F_ONLINK;
	if (metric)
		nla_put(m, RTA_PRIORITY, 4, &metric);
	nla_put(m, RTA_GATEWAY, 4, gw);
	if (ifindex)
		nla_put(m, RTA_OIF, 4, &ifindex);
	if (table >= 256) {
		uint32_t t = table;
		nla_put(m, RTA_TABLE, 4, &t);
	}
	return nl_send_sync(sk, m); /* consumes m */
}

static int nl_route_add_default(struct nl_sock *sk, int ifindex, const struct in_addr *gw,
    uint32_t metric)
{
	return nl_route_add_default_table(sk, ifindex, gw, metric, RT_TABLE_MAIN);
}

/* Pinned /32 host route to the DHCP server-id via the on-link lease gateway.
 * It survives a gateway-probe failover that moves the default route, so
 * unicast DHCPREQUESTs keep reaching the server that owns the lease. */
static int nl_route_add_host(struct nl_sock *sk, int ifindex, const struct in_addr *dst,
    const struct in_addr *gw)
{
	struct nl_msg *m = nlmsg_alloc_simple(RTM_NEWROUTE,
	    NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK);
	struct rtmsg *rt;

	if (!m)
		return -1;
	rt = (struct rtmsg *) nlmsg_reserve(m, sizeof(*rt), NLA_ALIGNTO);
	if (!rt) {
		nlmsg_free(m);
		return -1;
	}
	rt->rtm_family = AF_INET;
	rt->rtm_dst_len = 32;
	rt->rtm_src_len = 0;
	rt->rtm_tos = 0;
	rt->rtm_table = RT_TABLE_MAIN;
	rt->rtm_protocol = RTPROT_BOOT;
	rt->rtm_scope = RT_SCOPE_UNIVERSE;
	rt->rtm_type = RTN_UNICAST;
	rt->rtm_flags = RTNH_F_ONLINK; /* the lease gateway is on-link on the DHCP link */
	nla_put(m, RTA_DST, 4, dst);
	nla_put(m, RTA_GATEWAY, 4, gw);
	nla_put(m, RTA_OIF, 4, &ifindex);
	return nl_send_sync(sk, m); /* consumes m */
}

/* Split-prefix route for seamless-takeover steering: a more-specific prefix
 * (e.g. 0.0.0.0/1 or 128.0.0.0/1) via the new master's fabric nexthop. The
 * nexthop is on-link on the fabric, so no explicit device/ONLINK is pinned. */
static int nl_route_add_prefix(struct nl_sock *sk, const struct in_addr *dst,
    unsigned plen, const struct in_addr *gw)
{
	struct nl_msg *m = nlmsg_alloc_simple(RTM_NEWROUTE,
	    NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK);
	struct rtmsg *rt;

	if (!m)
		return -1;
	rt = (struct rtmsg *) nlmsg_reserve(m, sizeof(*rt), NLA_ALIGNTO);
	if (!rt) {
		nlmsg_free(m);
		return -1;
	}
	rt->rtm_family = AF_INET;
	rt->rtm_dst_len = (unsigned char)plen;
	rt->rtm_src_len = 0;
	rt->rtm_tos = 0;
	rt->rtm_table = RT_TABLE_MAIN;
	rt->rtm_protocol = RTPROT_STATIC;
	rt->rtm_scope = RT_SCOPE_UNIVERSE;
	rt->rtm_type = RTN_UNICAST;
	nla_put(m, RTA_DST, 4, dst);
	nla_put(m, RTA_GATEWAY, 4, gw);
	return nl_send_sync(sk, m); /* consumes m */
}

static int nl_rule_set_lookup_table(struct nl_sock *sk, uint32_t table, uint32_t prio, bool add)
{
	struct rtnl_rule *rule = rtnl_rule_alloc();
	int rc;
	if (!rule)
		return -1;
	rtnl_rule_set_family(rule, AF_INET);
	rtnl_rule_set_table(rule, table);
	if (prio)
		rtnl_rule_set_prio(rule, prio);
	if (add)
		rc = rtnl_rule_add(sk, rule, NLM_F_CREATE | NLM_F_ACK);
	else
		rc = rtnl_rule_delete(sk, rule, 0);
	if (rc == -NLE_EXIST && add)
		rc = 0;
	if (rc == -NLE_OBJ_NOTFOUND && !add)
		rc = 0;
	rtnl_rule_put(rule);
	return rc;
}

/* Program the cached gateway hardware address as a permanent neighbor entry
 * (RTM_NEWNEIGH, NUD_PERMANENT) so forwarding via the gateway works without
 * re-discovering it with ARP after a failover. Idempotent: an entry that
 * already carries the cached lladdr is left alone. */
static void apply_gw_neigh(int ifindex, const struct in_addr *gw,
    const uint8_t mac[HADC_MAC_LEN], const char *reason)
{
	struct nl_cache *ncache = NULL;
	struct rtnl_neigh *cur, *n;
	struct nl_addr *dst;
	char gwbuf[INET_ADDRSTRLEN];
	int rc;

	if (!g_sk)
		return;
	hadc_ipv4_format(*gw, gwbuf, sizeof(gwbuf));
	dst = nl_addr_build(AF_INET, (void *)gw, 4);
	if (!dst)
		return;
	if (hadc_nl_alloc_caches(g_sk, NULL, NULL, NULL, &ncache) < 0 || !ncache) {
		hadc_warn("executor: neighbor cache dump failed (gateway %s cache not "
		    "programmed, reason=%s)", gwbuf, reason);
		nl_addr_put(dst);
		return;
	}
	cur = rtnl_neigh_get(ncache, ifindex, dst);
	if (cur) {
		struct nl_addr *ll = rtnl_neigh_get_lladdr(cur);
		if (ll && nl_addr_get_len(ll) == HADC_MAC_LEN &&
		    memcmp(nl_addr_get_binary_addr(ll), mac, HADC_MAC_LEN) == 0) {
			hadc_dbg("executor: neighbor entry for %s already holds the cached "
			    "lladdr", gwbuf);
			rtnl_neigh_put(cur);
			nl_cache_drop(&ncache);
			nl_addr_put(dst);
			return;
		}
		rtnl_neigh_put(cur);
	}
	n = rtnl_neigh_alloc();
	if (!n) {
		nl_cache_drop(&ncache);
		nl_addr_put(dst);
		return;
	}
	rtnl_neigh_set_family(n, AF_INET);
	rtnl_neigh_set_ifindex(n, ifindex);
	rtnl_neigh_set_state(n, NUD_PERMANENT);
		{
			struct nl_addr *ll = nl_addr_build(AF_UNSPEC, (void *)mac, HADC_MAC_LEN);
			if (!ll || rtnl_neigh_set_dst(n, nl_addr_clone(dst)) < 0) {
				if (ll)
					nl_addr_put(ll);
				hadc_warn("executor: building neighbor entry for %s failed (reason=%s)",
				    gwbuf, reason);
				rtnl_neigh_put(n);
				nl_cache_drop(&ncache);
				nl_addr_put(dst);
				return;
			}
			rtnl_neigh_set_lladdr(n, ll); /* takes ownership */
		}
	rc = rtnl_neigh_add(g_sk, n, NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK);
	if (rc < 0)
		hadc_warn("executor: programming permanent neighbor %s -> "
		    "%02x:%02x:%02x:%02x:%02x:%02x failed: %s", gwbuf, mac[0],
		    mac[1], mac[2], mac[3], mac[4], mac[5], nl_geterror(rc));
	else
		hadc_info("executor: programmed permanent neighbor %s -> "
		    "%02x:%02x:%02x:%02x:%02x:%02x on ifindex %d (reason=%s)",
		    gwbuf, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
		    ifindex, reason);
	rtnl_neigh_put(n);
	nl_cache_drop(&ncache);
	nl_addr_put(dst);
}

/* Observe the gateway's hardware address from this node's neighbor table
 * (master-side cache population: only states the kernel would actually use
 * for forwarding count). 0 = learned, -1 = nothing resolved. */
int hadc_executor_observe_gw_mac(hadc_ctx_t *ctx, uint8_t mac[HADC_MAC_LEN])
{
	struct nl_cache *lcache = NULL, *ncache = NULL;
	struct rtnl_link *link = NULL;
	struct nl_addr *dst = NULL;
	struct rtnl_neigh *n = NULL;
	int rc = -1;

	hadc_maint_lock();
	if (!g_sk || !ctx->lease.gateway.s_addr)
		goto out;
	dst = nl_addr_build(AF_INET, (void *)&ctx->lease.gateway, 4);
	if (!dst)
		goto out;
	if (hadc_nl_alloc_caches(g_sk, &lcache, NULL, NULL, &ncache) < 0 || !lcache || !ncache) {
		hadc_dbg("executor: neighbor observation: netlink cache dump failed");
		goto out;
	}
	link = rtnl_link_get_by_name(lcache, ctx->conf.interface);
	if (!link) {
		hadc_dbg("executor: neighbor observation: interface %s not found",
		    ctx->conf.interface);
		goto out;
	}
	n = rtnl_neigh_get(ncache, rtnl_link_get_ifindex(link), dst);
	if (!n)
		goto out;
	switch (rtnl_neigh_get_state(n)) {
	case NUD_REACHABLE:
	case NUD_DELAY:
	case NUD_STALE:
	case NUD_PERMANENT:
		break;
	default:
		goto out; /* unresolved or not usable for forwarding */
	}
	{
		struct nl_addr *ll = rtnl_neigh_get_lladdr(n);
		if (ll && nl_addr_get_len(ll) == HADC_MAC_LEN) {
			memcpy(mac, nl_addr_get_binary_addr(ll), HADC_MAC_LEN);
			rc = 0;
		}
	}
out:
	if (n)
		rtnl_neigh_put(n);
	if (link)
		rtnl_link_put(link);
	nl_cache_drop(&lcache);
	nl_cache_drop(&ncache);
	nl_addr_put(dst);
	hadc_maint_unlock();
	return rc;
}


static bool vip_neigh_collectable_ifindex(struct nl_cache *lcache, const char *ifname, int *out_ifindex)
{
    struct rtnl_link *link = rtnl_link_get_by_name(lcache, ifname);
    if (!link)
        return false;
    *out_ifindex = rtnl_link_get_ifindex(link);
    rtnl_link_put(link);
    return true;
}

/* Collect resolved IPv4 neighbors on cluster/VIP interfaces (master-side). */
int hadc_executor_collect_vip_neighs(hadc_ctx_t *ctx, bool force_push)
{
    struct nl_cache *lcache = NULL, *ncache = NULL;
    hadc_vip_neigh_t *out = NULL;
    size_t n = 0, cap = 0;
    bool do_push = false, did_change = false, collected = false;
    size_t log_n = 0;
    int rc = -1;

    hadc_maint_lock();
    if (!g_sk || !ctx->conf.cluster.neighbor_sync || ctx->conf.n_members == 0 ||
        ctx->conf.cluster.neighbor_sync_max == 0)
        goto out_unlock;
    if (ctx->role != HADC_ROLE_MASTER && ctx->role != HADC_ROLE_PROMOTING)
        goto out_unlock;
    if (hadc_nl_alloc_caches(g_sk, &lcache, NULL, NULL, &ncache) < 0 || !lcache || !ncache)
        goto out_unlock;

    cap = ctx->conf.cluster.neighbor_sync_max;
    out = calloc(cap, sizeof(*out));
    if (!out)
        goto out_unlock;

    /* iterate configured cluster interfaces and pick resolved neighbors.
     * Include usable states (REACHABLE/STALE/DELAY/PROBE/PERMANENT) so kernel
     * reachability-timer transitions do not churn the snapshot; updates reflect
     * add/delete or IP/MAC changes only. */
    for (size_t ci = 0; ci < ctx->conf.cluster.n_ifaces && n < cap; ci++) {
        int ifindex;
        const char *ifname = ctx->conf.cluster.ifaces[ci].interface;
        if (!vip_neigh_collectable_ifindex(lcache, ifname, &ifindex))
            continue;
        for (struct nl_object *obj = nl_cache_get_first(ncache); obj && n < cap;
             obj = nl_cache_get_next(obj)) {
            struct rtnl_neigh *ne = (struct rtnl_neigh *)obj;
            int state = rtnl_neigh_get_state(ne);
            if (rtnl_neigh_get_ifindex(ne) != ifindex)
                continue;
            if (rtnl_neigh_get_family(ne) != AF_INET)
                continue;
            if (!(state & (NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT)))
                continue;
            struct nl_addr *dst = rtnl_neigh_get_dst(ne);
            struct nl_addr *ll = rtnl_neigh_get_lladdr(ne);
            if (!dst || nl_addr_get_len(dst) != 4 || !ll || nl_addr_get_len(ll) != HADC_MAC_LEN)
                continue;
            hadc_vip_neigh_t *e = &out[n];
            memset(e, 0, sizeof(*e));
            snprintf(e->ifname, sizeof(e->ifname), "%s", ifname);
            memcpy(&e->ip, nl_addr_get_binary_addr(dst), 4);
            memcpy(e->mac, nl_addr_get_binary_addr(ll), HADC_MAC_LEN);
            n++;
        }
    }

    /* stable order for comparison/push */
    if (n > 1) {
        int cmp(const void *a, const void *b) {
            const hadc_vip_neigh_t *x = a, *y = b;
            int c = strcmp(x->ifname, y->ifname);
            if (c) return c;
            if (x->ip.s_addr != y->ip.s_addr)
                return (ntohl(x->ip.s_addr) < ntohl(y->ip.s_addr)) ? -1 : 1;
            return memcmp(x->mac, y->mac, HADC_MAC_LEN);
        }
        qsort(out, n, sizeof(out[0]), cmp);
    }

    {
        bool changed = (n != ctx->n_vip_neighs) ||
            (n && (!ctx->vip_neighs || memcmp(out, ctx->vip_neighs, n * sizeof(out[0])) != 0));
        if (changed) {
            hadc_vip_neigh_t *np = NULL;
            if (n > 0) {
                np = malloc(n * sizeof(*np));
                if (np) {
                    memcpy(np, out, n * sizeof(*np));
                } else {
                    hadc_warn("executor: vip neighbor snapshot alloc failed; keeping previous snapshot");
                    changed = false;
                }
            }
            if (changed) {
                free(ctx->vip_neighs);
                ctx->vip_neighs = np;
                ctx->n_vip_neighs = n;
                ctx->vip_neighs_cap = n;
                did_change = true;
                log_n = n;
            }
        }
        collected = true;
        do_push = force_push || did_change;
        rc = did_change ? 1 : 0;
    }

out_unlock:
    nl_cache_drop(&lcache);
    nl_cache_drop(&ncache);
    hadc_maint_unlock();

    if (collected && do_push)
        hadc_cluster_push_state(ctx, &ctx->lease);
    if (did_change)
        hadc_info("executor: vip neighbor snapshot updated (%zu entries)", log_n);

    free(out);
    return rc;
}

/* Apply synced VIP neighbors on cluster interfaces as non-permanent entries.
 * Called during VIP install/promotion path; requires interface/link context. */
static void hadc_executor_apply_vip_neighs(hadc_ctx_t *ctx, const hadc_desired_t *desired,
    struct nl_cache *lcache)
{
    if (!g_sk || !ctx->conf.cluster.neighbor_sync || !desired || !desired->cluster_addrs_present)
        return;
    for (size_t i = 0; i < ctx->n_vip_neighs; i++) {
        const hadc_vip_neigh_t *vn = &ctx->vip_neighs[i];
        /* only for interfaces we are bringing up as VIP owner now */
        bool want_if = false;
        for (size_t j = 0; j < desired->n_cluster_ifaces; j++)
            if (!strcmp(desired->cluster_ifaces[j].interface, vn->ifname)) { want_if = true; break; }
        if (!want_if)
            continue;
        struct rtnl_link *link = rtnl_link_get_by_name(lcache, vn->ifname);
        if (!link)
            continue;
        int ifindex = rtnl_link_get_ifindex(link);
        struct rtnl_neigh *n = rtnl_neigh_alloc();
        struct nl_addr *dst = nl_addr_build(AF_INET, (void *)&vn->ip, 4);
        struct nl_addr *ll = nl_addr_build(AF_UNSPEC, (void *)vn->mac, HADC_MAC_LEN);
        if (n && dst && ll) {
            rtnl_neigh_set_family(n, AF_INET);
            rtnl_neigh_set_ifindex(n, ifindex);
            rtnl_neigh_set_state(n, NUD_REACHABLE);
            rtnl_neigh_set_dst(n, dst); dst = NULL; /* takes ownership */
            rtnl_neigh_set_lladdr(n, ll); ll = NULL;
            int rc = rtnl_neigh_add(g_sk, n, NLM_F_CREATE | NLM_F_REPLACE);
            if (rc < 0 && rc != -NLE_EXIST) {
                char vnbuf[INET_ADDRSTRLEN];
                hadc_dbg("executor: vip neighbor %s dev %s add: %s", hadc_ipv4_format(vn->ip, vnbuf, sizeof(vnbuf)), vn->ifname, nl_geterror(rc));
            }
        }
        if (dst) nl_addr_put(dst);
        if (ll) nl_addr_put(ll);
        if (n) rtnl_neigh_put(n);
        rtnl_link_put(link);
    }
}


/* Does the neighbor cache hold an entry for gw carrying exactly this lladdr? */
static bool neigh_holds(struct nl_cache *ncache, int ifindex,
    const struct in_addr *gw, const uint8_t mac[HADC_MAC_LEN])
{
	struct nl_addr *dst = nl_addr_build(AF_INET, (void *)gw, 4);
	struct rtnl_neigh *n;
	bool ok = false;

	if (!dst)
		return false;
	n = rtnl_neigh_get(ncache, ifindex, dst);
	if (n) {
		struct nl_addr *ll = rtnl_neigh_get_lladdr(n);
		ok = ll && nl_addr_get_len(ll) == HADC_MAC_LEN &&
		     memcmp(nl_addr_get_binary_addr(ll), mac, HADC_MAC_LEN) == 0;
		rtnl_neigh_put(n);
	}
	nl_addr_put(dst);
	return ok;
}

/* Drift verification: compare the desired state against live kernel state for
 * the resources we own (lease address, cluster addresses, default routes,
 * programmed neighbor entry, link state). DNS is hook-managed and not
 * verified here. Returns the number of diverged managed rows (0 = matches),
 * or -1 when live state cannot be read. */
static int verify_desired(hadc_ctx_t *ctx, const hadc_desired_t *d)
{
	struct nl_cache *lcache = NULL, *acache = NULL, *rcache = NULL, *ncache = NULL;
	struct rtnl_link *link = NULL;
	int drift = 0;

	if (!g_sk)
		return -1;
	if (hadc_nl_alloc_caches(g_sk, &lcache, &acache, &rcache, &ncache) < 0) {
		hadc_dbg("executor: drift verify: netlink cache dump failed");
		return -1;
	}
	link = rtnl_link_get_by_name(lcache, d->interface);
	if (!link) {
		hadc_dbg("executor: drift verify: interface %s not found", d->interface);
		drift = -1;
		goto out;
	}
	{
		int ifindex = rtnl_link_get_ifindex(link);
		bool up = rtnl_link_get_flags(link) & IFF_UP;

		if ((d->link_state == 1 && !up) || (d->link_state == 2 && up))
			drift++;
		if (d->present && !find_addr(acache, ifindex, &d->address,
		    (int)d->prefixlen))
			drift++;
		/* The cluster address set is ours in both roles: the master must hold
		 * it, a slave must not (a leftover from a previous life as master
		 * counts as drift, matching apply_cluster_addrs). */
		if (d->cluster_addrs_present ||
		    (g_applied_valid && g_applied.cluster_addrs_present)) {
			for (size_t i = 0; i < d->n_cluster_ifaces; i++) {
				const hadc_cluster_if_t *ci = &d->cluster_ifaces[i];
				struct rtnl_link *cl = rtnl_link_get_by_name(lcache,
				    ci->interface);
				if (!cl) {
					if (ci->n_addrs)
						drift++;
					continue;
				}
				for (size_t j = 0; j < ci->n_addrs; j++) {
					struct rtnl_addr *a = find_addr(acache,
					    rtnl_link_get_ifindex(cl), &ci->addrs[j].address, -1);
					bool exact = a && (unsigned)rtnl_addr_get_prefixlen(a) ==
					    ci->addrs[j].prefixlen;
					if (d->cluster_addrs_present ? !exact
					    : (a && exact))
						drift++;
				}
				rtnl_link_put(cl);
			}
		}
		if (d->add_routes) {
			const struct in_addr *via = default_nexthop(d);

			if (via->s_addr && !find_default(rcache, via))
				drift++;
			if (d->backup_route && d->backup_gateway.s_addr &&
			    d->backup_gateway.s_addr != via->s_addr &&
			    !find_default(rcache, &d->backup_gateway))
				drift++;
			if (d->gw_mac_valid && d->gateway.s_addr &&
			    !neigh_holds(ncache, ifindex, &d->gateway, d->gw_mac))
				drift++;
			if (server_needs_pin(d) &&
			    !find_host_route(rcache, &d->server_id, &d->gateway))
				drift++;
		}
		/* Seamless-takeover steering routes (split /1s plus VIP splits) are
		 * ours while steering is on (must exist) and gone once it is off (must
		 * not linger). */
		if (d->steer_via.s_addr || (g_applied_valid && g_applied.steer_via.s_addr)) {
			static const struct in_addr low;
			struct in_addr high;
			const struct in_addr *split[2] = { &low, &high };
			const hadc_desired_t *eff = d->steer_via.s_addr ? d : &g_applied;
			const struct in_addr *via = &eff->steer_via;
			vip_split_t vips[VIP_SPLIT_MAX];
			size_t n_vips;
			high.s_addr = htonl(0x80000000u);
			for (size_t i = 0; i < 2; i++) {
				bool present = find_prefix_route(rcache, split[i], 1, via) != NULL;
				if (d->steer_via.s_addr ? !present : present)
					drift++;
			}
			n_vips = vip_splits(eff, via, vips, VIP_SPLIT_MAX);
			for (size_t i = 0; i < n_vips; i++) {
				bool present = find_prefix_route(rcache, &vips[i].net, vips[i].plen, via) != NULL;
				if (d->steer_via.s_addr ? !present : present)
					drift++;
			}
		}
	}
out:
	if (link)
		rtnl_link_put(link);
	nl_cache_drop(&lcache);
	nl_cache_drop(&acache);
	nl_cache_drop(&rcache);
	nl_cache_drop(&ncache);
	(void)ctx;
	return drift;
}

static void reconcile_now(hadc_ctx_t *ctx, const char *reason)
{
	hadc_desired_t desired;
	int v;

	if (!g_applied_valid)
		return; /* nothing applied yet: nothing to reconcile against */
	hadc_executor_desired(ctx, &ctx->lease, &desired);
	v = verify_desired(ctx, &desired);
	g_last_verify = v < 0 ? -1 : (v > 0 ? 1 : 0);
	if (v <= 0)
		return;
	g_drift_reconciled++;
	hadc_info("executor: drift detected (%d managed row(s) diverged, reason=%s); "
	    "re-applying", v, reason);
	executor_apply_locked(ctx, &desired, reason, true);
}

void hadc_executor_audit_tick(hadc_ctx_t *ctx)
{
	hadc_maint_lock();
	if (ctx->conf.cluster.neighbor_sync &&
	    (ctx->role == HADC_ROLE_MASTER || ctx->role == HADC_ROLE_PROMOTING)) {
		uint64_t now = (uint64_t)hadc_now_ms();
		uint64_t iv = (uint64_t)ctx->conf.cluster.neighbor_sync_resync_s * 1000ULL;
		bool never = (ctx->vip_neigh_last_resync_ms == 0);
		bool periodic = (ctx->conf.cluster.neighbor_sync_resync_s > 0 &&
		    (never || now - ctx->vip_neigh_last_resync_ms >= iv));
		bool due = g_vip_neigh_pending &&
		    (now - g_last_vip_neigh_collect_ms >= HADC_EXECUTOR_RECONCILE_MIN_INTERVAL_MS);
		if (never || periodic || due) {
			bool initial = never;
			g_vip_neigh_pending = false;
			g_last_vip_neigh_collect_ms = now;
			ctx->vip_neigh_last_resync_ms = now ? now : 1;
			hadc_maint_unlock();
			hadc_executor_collect_vip_neighs(ctx, initial); /* initial snapshot: push once */
			hadc_maint_lock();
		}
	} else {
		g_vip_neigh_pending = false;
	}
	/* Pending monitor events are acted on the first heartbeat tick after the
	 * debounce interval, so a burst (netifd flush+re-add) settles first. */
	if (g_mon_pending && (uint64_t)hadc_now_ms() - g_mon_last_reconcile_ms >=
	    HADC_EXECUTOR_RECONCILE_MIN_INTERVAL_MS) {
		g_mon_pending = false;
		g_mon_last_reconcile_ms = (uint64_t)hadc_now_ms();
		reconcile_now(ctx, "RECONCILE");
		hadc_maint_unlock();
		return;
	}
	if ((uint64_t)hadc_now_ms() - g_last_audit_ms < HADC_EXECUTOR_AUDIT_MS) {
		hadc_maint_unlock();
		return;
	}
	g_last_audit_ms = (uint64_t)hadc_now_ms();
	reconcile_now(ctx, "AUDIT");
	hadc_maint_unlock();
}

int hadc_executor_monitor_start(hadc_ctx_t *ctx)
{
	if (!g_sk) {
		hadc_warn("executor: monitor start needs the netlink command socket first");
		return -1;
	}
	g_mon_sk = nl_socket_alloc();
	if (!g_mon_sk) {
		hadc_warn("executor: monitor nl_socket_alloc failed");
		return -1;
	}
	if (nl_connect(g_mon_sk, NETLINK_ROUTE) != 0) {
		hadc_warn("executor: monitor netlink connect failed; drift detection "
		    "falls back to the periodic audit");
		nl_socket_free(g_mon_sk);
		g_mon_sk = NULL;
		return -1;
	}
	/* libnl group numbers, i.e. the RTMGRP bind-mask bit + 1: 1 = link,
	 * 3 = neighbor (RTMGRP_NEIGH), 5 = IPv4 ifaddr, 7 = IPv4 route. */
	if (nl_socket_add_memberships(g_mon_sk, 1, 3, 5, 7, 0) < 0) {
		hadc_warn("executor: monitor netlink memberships failed; drift detection "
		    "falls back to the periodic audit");
		nl_socket_free(g_mon_sk);
		g_mon_sk = NULL;
		return -1;
	}
	nl_socket_set_nonblocking(g_mon_sk);
	g_mon_fd = nl_socket_get_fd(g_mon_sk);
	if (hadc_loop_add(ctx, g_mon_fd, monitor_ready, 0) != 0) {
		hadc_warn("executor: monitor fd could not be registered");
		nl_socket_free(g_mon_sk);
		g_mon_sk = NULL;
		g_mon_fd = -1;
		return -1;
	}
	hadc_info("executor: rtnetlink drift monitor active (addr/route/neigh/link groups)");
	return 0;
}

/* Drain the multicast queue and mark a pending verify; the heartbeat tick
 * acts on it after the debounce interval, so a burst settles first. Our own
 * changes arrive here too — verify then matches and nothing re-applies. */
static void monitor_ready(hadc_ctx_t *ctx, int fd)
{
	char buf[4096];
	bool got = false;

	hadc_maint_lock();
	while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
		g_mon_pending = true;
		got = true;
	}
	if (got && ctx && ctx->conf.cluster.neighbor_sync &&
	    (ctx->role == HADC_ROLE_MASTER || ctx->role == HADC_ROLE_PROMOTING))
		g_vip_neigh_pending = true;
	hadc_maint_unlock();
}

json_t *hadc_executor_status(void)
{
	char hash[65] = "";

	hadc_maint_lock();
	if (g_applied_valid) {
		for (size_t i = 0; i < 32; i++)
			snprintf(hash + i * 2, 3, "%02x", g_applied.config_hash[i]);
	}
	json_t *o = json_pack("{s:s, s:I, s:I, s:b}", "applied_hash", hash, "verified",
	    (json_int_t)g_last_verify, "drift_reconciled", (json_int_t)g_drift_reconciled,
	    "monitor", g_mon_fd >= 0);
	hadc_maint_unlock();
	return o;
}

int hadc_executor_apply(hadc_ctx_t *ctx, const hadc_desired_t *desired, const char *reason)
{
	hadc_maint_lock();
	if (g_applied_valid && !memcmp(g_applied.config_hash, desired->config_hash,
	    sizeof(g_applied.config_hash))) {
		/* The memo says applied — but it is a fast path, not the truth: an
		 * external manager (netifd reload, ip addr flush) may have removed
		 * what we applied. Verify against live state before declaring a
		 * no-op. */
		int v = verify_desired(ctx, desired);
		g_last_verify = v < 0 ? -1 : (v > 0 ? 1 : 0);
		if (v == 0) {
			hadc_dbg("executor: desired state already applied (no delta, reason=%s)",
			    reason);
			hadc_maint_unlock();
			return 0;
		}
		if (v > 0) {
			g_drift_reconciled++;
			hadc_info("executor: drift detected during apply (%d managed row(s) "
			    "diverged, reason=%s); reconciling live state", v, reason);
		}
	}
	int rc = executor_apply_locked(ctx, desired, reason, false);
	hadc_maint_unlock();
	return rc;
}

static int executor_apply_locked(hadc_ctx_t *ctx, const hadc_desired_t *desired,
    const char *reason, bool from_drift)
{
	struct nl_cache *lcache = NULL, *acache = NULL, *rcache = NULL;
	struct rtnl_link *link;
	struct rtnl_addr *stale;
	struct rtnl_route *sroute;
	const hadc_desired_t *prev = g_applied_valid ? &g_applied : NULL;
	int ifindex, fatal = 0, ar = 0;

	if (!g_sk) {
		hadc_err("executor: netlink socket not open");
		return -1;
	}
	hadc_info("executor: apply %s reason=%s interface=%s present=%d hash=%02x%02x%02x%02x",
	    from_drift ? "drift" : "delta", reason, desired->interface, desired->present,
	    desired->config_hash[0], desired->config_hash[1], desired->config_hash[2],
	    desired->config_hash[3]);

	if (hadc_nl_alloc_caches(g_sk, &lcache, &acache, &rcache, NULL) < 0) {
		hadc_warn("executor: netlink cache dump failed");
		if (executor_action_is_fatal(-1, true))
			fatal = -1;
		goto out;
	}
	link = rtnl_link_get_by_name(lcache, desired->interface);
	if (!link) {
		hadc_warn("executor: interface %s not found", desired->interface);
		if (executor_action_is_fatal(-1, true))
			fatal = -1;
		goto out;
	}
	ifindex = rtnl_link_get_ifindex(link);

	if (desired->link_state == 1 && !(rtnl_link_get_flags(link) & IFF_UP)) {
		if ((ar = nl_link_set_state(g_sk, ifindex, true)) < 0)
			hadc_warn("executor: bringing link %s up failed: %s",
			    desired->interface, nl_geterror(ar));
		else
			hadc_info("executor: link %s brought up (reason=%s)",
			    desired->interface, reason);
	}

	/* Address reconcile: remove only what we applied, add the desired one;
	   addresses we never applied (e.g. per-node sync secondaries) stay. */
	if (prev && prev->present &&
	    (!desired->present || desired->address.s_addr != prev->address.s_addr ||
	    desired->prefixlen != prev->prefixlen)) {
		stale = find_addr(acache, ifindex, &prev->address, prev->prefixlen);
		if (stale) {
			char abuf[INET_ADDRSTRLEN];
			hadc_ipv4_format(prev->address, abuf, sizeof(abuf));
			if ((ar = rtnl_addr_delete(g_sk, stale, 0)) < 0)
				hadc_warn("executor: deleting address %s/%u failed: %s",
				    abuf, prev->prefixlen, nl_geterror(ar));
			else
				hadc_info("executor: removed address %s/%u from %s (reason=%s)",
				    abuf, prev->prefixlen, desired->interface, reason);
		}
	}
	if (desired->present) {
		char abuf[INET_ADDRSTRLEN];
		hadc_ipv4_format(desired->address, abuf, sizeof(abuf));
		struct rtnl_addr *cur = find_addr(acache, ifindex, &desired->address, -1);
		if (cur && (unsigned)rtnl_addr_get_prefixlen(cur) != desired->prefixlen) {
			/* Same address, wrong prefix (e.g. left over by an older
			   build): replace it, it is our lease address. */
			if ((ar = rtnl_addr_delete(g_sk, cur, 0)) < 0)
				hadc_warn("executor: replacing address %s/%u failed: %s",
				    abuf, (unsigned)rtnl_addr_get_prefixlen(cur), nl_geterror(ar));
			else
				hadc_info("executor: replaced address %s/%u on %s (reason=%s)",
				    abuf, (unsigned)rtnl_addr_get_prefixlen(cur),
				    desired->interface, reason);
			cur = NULL;
		}
		if (!cur) {
			if ((ar = nl_addr_add(g_sk, ifindex, &desired->address,
			    desired->prefixlen)) < 0)
				hadc_warn("executor: adding address %s/%u failed: %s",
				    abuf, desired->prefixlen, nl_geterror(ar));
			else
				hadc_info("executor: added address %s/%u on %s (reason=%s)",
				    abuf, desired->prefixlen, desired->interface, reason);
		} else {
			hadc_dbg("executor: address %s/%u already present on %s",
			    abuf, desired->prefixlen, desired->interface);
		}
	}

	apply_cluster_addrs(ctx, lcache, acache, desired, prev, reason);

	if (desired->add_routes) {
		struct route_collect conflicts = { { NULL }, 0 };
		const struct in_addr *via = default_nexthop(desired);
		size_t ci;
		bool wiped = false;
		bool want_backup = desired->backup_route && desired->backup_gateway.s_addr != 0 &&
		    desired->backup_gateway.s_addr != via->s_addr;

		if (desired->gateway.s_addr && desired->gw_mac_valid)
			apply_gw_neigh(ifindex, &desired->gateway, desired->gw_mac, reason);

		/* Pin the DHCP server-id with a /32 via the on-link lease gateway so a
		 * gateway-probe failover that moves the default route cannot blackhole
		 * unicast DHCPREQUESTs. Idempotent; a stale pin is dropped when the
		 * server-id or gateway changes or it is no longer needed. */
		if (server_needs_pin(desired)) {
			char sidbuf[INET_ADDRSTRLEN], gwbuf[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &desired->server_id, sidbuf, sizeof(sidbuf));
			inet_ntop(AF_INET, &desired->gateway, gwbuf, sizeof(gwbuf));
			if (prev && server_needs_pin(prev) &&
			    (prev->server_id.s_addr != desired->server_id.s_addr ||
			    prev->gateway.s_addr != desired->gateway.s_addr)) {
				sroute = find_host_route(rcache, &prev->server_id, &prev->gateway);
				if (sroute) {
					char pbuf[INET_ADDRSTRLEN];
					hadc_ipv4_format(prev->server_id, pbuf, sizeof(pbuf));
					if ((ar = rtnl_route_delete(g_sk, sroute, 0)) < 0)
						hadc_warn("executor: deleting stale server pin to %s "
						    "failed: %s", pbuf, nl_geterror(ar));
					else
						hadc_info("executor: removed stale server pin to %s "
						    "(reason=%s)", pbuf, reason);
				}
			}
			if (!find_host_route(rcache, &desired->server_id, &desired->gateway)) {
				if ((ar = nl_route_add_host(g_sk, ifindex, &desired->server_id,
				    &desired->gateway)) < 0)
					hadc_warn("executor: adding server pin /32 to %s via %s "
					    "failed: %s", sidbuf, gwbuf, nl_geterror(ar));
				else
					hadc_info("executor: pinned server-id %s via %s on %s "
					    "(reason=%s)", sidbuf, gwbuf, desired->interface, reason);
			}
		} else if (prev && server_needs_pin(prev)) {
			sroute = find_host_route(rcache, &prev->server_id, &prev->gateway);
			if (sroute) {
				char pbuf[INET_ADDRSTRLEN];
				hadc_ipv4_format(prev->server_id, pbuf, sizeof(pbuf));
				if ((ar = rtnl_route_delete(g_sk, sroute, 0)) < 0)
					hadc_warn("executor: deleting server pin /32 to %s failed: %s",
					    pbuf, nl_geterror(ar));
				else
					hadc_info("executor: removed server pin /32 to %s (reason=%s)",
					    pbuf, reason);
			}
		}

		if (via->s_addr) {
			char viabuf[INET_ADDRSTRLEN];
			hadc_ipv4_format(*via, viabuf, sizeof(viabuf));
			sroute = find_default(rcache, via);
			if (sroute) {
				hadc_dbg("executor: default route via %s already present", viabuf);
			} else {
				/* Remove every conflicting default-route entry
				   (ours from before, netifd's, any type). */
				nl_cache_foreach(rcache, route_collect_cb, &conflicts);
				for (ci = 0; ci < conflicts.n; ci++) {
					if ((ar = rtnl_route_delete(g_sk, conflicts.out[ci], 0)) < 0)
						hadc_warn("executor: deleting conflicting "
						    "default route (type %d) failed: %s",
						    rtnl_route_get_type(conflicts.out[ci]),
						    nl_geterror(ar));
					else
						hadc_info("executor: removed conflicting "
						    "default route (type %d, reason=%s)",
						    rtnl_route_get_type(conflicts.out[ci]), reason);
				}
				/* The override nexthop lives on another link (the
				   backup router is on the LAN), so let the kernel pick
				   the device; only the lease gateway is on-link on the
				   DHCP interface. */
				int oif = desired->default_via.s_addr ? 0 : ifindex;
				if ((ar = nl_route_add_default(g_sk, oif, via, 0)) < 0)
					hadc_warn("executor: adding default route via %s failed: %s",
					    viabuf, nl_geterror(ar));
				else
					hadc_info("executor: added default route via %s on %s (reason=%s)",
					    viabuf, desired->interface, reason);
				wiped = true;
			}
		} else if (prev && default_nexthop(prev)->s_addr) {
			/* the gateway went away: drop what we applied */
			const struct in_addr *pvia = default_nexthop(prev);
			sroute = find_default(rcache, pvia);
			if (sroute) {
				char pvbuf[INET_ADDRSTRLEN];
				hadc_ipv4_format(*pvia, pvbuf, sizeof(pvbuf));
				if ((ar = rtnl_route_delete(g_sk, sroute, 0)) < 0)
					hadc_warn("executor: deleting default route via %s failed: %s",
					    pvbuf, nl_geterror(ar));
				else
					hadc_info("executor: removed default route via %s (reason=%s)",
					    pvbuf, reason);
			}
		}

		if (!via->s_addr && want_backup) {
			/* Slave-only mode: only the backup default may remain. */
			nl_cache_foreach(rcache, route_collect_cb, &conflicts);
			for (ci = 0; ci < conflicts.n; ci++) {
				if ((ar = rtnl_route_delete(g_sk, conflicts.out[ci], 0)) < 0)
					hadc_warn("executor: deleting conflicting "
					    "default route (type %d) failed: %s",
					    rtnl_route_get_type(conflicts.out[ci]), nl_geterror(ar));
				else
					hadc_info("executor: removed conflicting "
					    "default route (type %d, reason=%s)",
					    rtnl_route_get_type(conflicts.out[ci]), reason);
			}
			if (conflicts.n)
				wiped = true;
		}

		/* Slave-only backup route: higher metric, so the lease-derived
		   primary wins whenever it exists and this takes over when it does
		   not. It is dropped again on promotion. */
		if (want_backup) {
			char bbuf[INET_ADDRSTRLEN];
			hadc_ipv4_format(desired->backup_gateway, bbuf, sizeof(bbuf));
			if (wiped || !find_default(rcache, &desired->backup_gateway)) {
				if ((ar = nl_route_add_default(g_sk, 0,
				    &desired->backup_gateway, HADC_BACKUP_ROUTE_METRIC)) < 0)
					hadc_warn("executor: adding backup default route via "
					    "%s failed: %s", bbuf, nl_geterror(ar));
				else
					hadc_info("executor: added backup default route via %s "
					    "metric %d (reason=%s)", bbuf, HADC_BACKUP_ROUTE_METRIC, reason);
			} else {
				hadc_dbg("executor: backup default route via %s already present", bbuf);
			}
		} else if (prev && prev->backup_route && prev->backup_gateway.s_addr &&
		    prev->backup_gateway.s_addr != via->s_addr) {
			sroute = find_default(rcache, &prev->backup_gateway);
			if (sroute) {
				char bbuf[INET_ADDRSTRLEN];
				hadc_ipv4_format(prev->backup_gateway, bbuf, sizeof(bbuf));
				if ((ar = rtnl_route_delete(g_sk, sroute, 0)) < 0)
					hadc_warn("executor: deleting backup default route via "
					    "%s failed: %s", bbuf, nl_geterror(ar));
				else
					hadc_info("executor: removed backup default route via %s "
					    "(reason=%s)", bbuf, reason);
			}
		}
		/* Optional: slave local-origin policy routing via master */
		if (desired->slave_sync_wan && desired->slave_wan_local_via_master && desired->slave_wan_local_table > 0 && desired->backup_gateway.s_addr != 0) {
			if ((ar = nl_rule_set_lookup_table(g_sk, (uint32_t)desired->slave_wan_local_table, 100, true)) < 0)
				hadc_warn("executor: adding policy rule for table %d failed: %s", desired->slave_wan_local_table, nl_geterror(ar));
			else
				hadc_info("executor: ensured policy rule lookup table %d (reason=%s)", desired->slave_wan_local_table, reason);
			if ((ar = nl_route_add_default_table(g_sk, 0, &desired->backup_gateway, 0, (uint32_t)desired->slave_wan_local_table)) < 0) {
				char bbuf[INET_ADDRSTRLEN];
				hadc_ipv4_format(desired->backup_gateway, bbuf, sizeof(bbuf));
				if (ar == -NLE_EXIST)
					hadc_dbg("executor: policy table %d default via %s already present", desired->slave_wan_local_table, bbuf);
				else
					hadc_warn("executor: adding default in table %d via %s failed: %s", desired->slave_wan_local_table, bbuf, nl_geterror(ar));
			} else {
				char bbuf[INET_ADDRSTRLEN];
				hadc_ipv4_format(desired->backup_gateway, bbuf, sizeof(bbuf));
				hadc_info("executor: added default route in table %d via %s (reason=%s)", desired->slave_wan_local_table, bbuf, reason);
			}
		} else if (prev && prev->slave_sync_wan && prev->slave_wan_local_via_master && prev->slave_wan_local_table > 0) {
			bool need_cleanup = false;
			if (!desired->slave_sync_wan || !desired->slave_wan_local_via_master || desired->slave_wan_local_table != prev->slave_wan_local_table)
				need_cleanup = true;
			else if (desired->backup_gateway.s_addr != prev->backup_gateway.s_addr || desired->backup_gateway.s_addr == 0)
				need_cleanup = true;
			if (need_cleanup) {
				if ((ar = nl_rule_set_lookup_table(g_sk, (uint32_t)prev->slave_wan_local_table, 100, false)) < 0)
					hadc_dbg("executor: removing policy rule for table %d: %s", prev->slave_wan_local_table, nl_geterror(ar));
				else
					hadc_info("executor: removed policy rule lookup table %d (reason=%s)", prev->slave_wan_local_table, reason);
				if (prev->backup_gateway.s_addr != 0) {
					char bbuf[INET_ADDRSTRLEN];
					hadc_ipv4_format(prev->backup_gateway, bbuf, sizeof(bbuf));
					if ((ar = nl_route_del_default_table(g_sk, (uint32_t)prev->slave_wan_local_table, &prev->backup_gateway)) < 0) {
						if (ar == -NLE_OBJ_NOTFOUND || ar == -NLE_NOADDR)
							hadc_dbg("executor: policy table %d default route via %s not present", prev->slave_wan_local_table, bbuf);
						else
							hadc_warn("executor: deleting policy table %d default route via %s failed: %s", prev->slave_wan_local_table, bbuf, nl_geterror(ar));
					} else
						hadc_info("executor: removed policy table %d default route via %s (reason=%s)", prev->slave_wan_local_table, bbuf, reason);
				}
			}
		}
	}

	/* Seamless takeover steering routes: additive split /1s plus per-VIP-subnet
	 * splits at prefixlen+1 via the new master's fabric nexthop. Longest-prefix
	 * match beats the default route without touching it (and beats the
	 * connected route for VIP subnets, steering their address space); the
	 * kernel's /32 local route for the VIP address itself still wins, so the
	 * nft scoping chains handle VIP-destination traffic. Explicit cleanup when
	 * the demoting hold ends. */
	{
		static const struct in_addr split_low = { 0 };
		struct in_addr split_high;
		const struct in_addr *split[2];
		vip_split_t vips[VIP_SPLIT_MAX];
		size_t n_vips;
		split_high.s_addr = htonl(0x80000000u);
		split[0] = &split_low;
		split[1] = &split_high;
		if (desired->steer_via.s_addr) {
			char viabuf[INET_ADDRSTRLEN];
			hadc_ipv4_format(desired->steer_via, viabuf, sizeof(viabuf));
			for (size_t i = 0; i < 2; i++) {
				char dstbuf[INET_ADDRSTRLEN];
				hadc_ipv4_format(*split[i], dstbuf, sizeof(dstbuf));
				if (find_prefix_route(rcache, split[i], 1, &desired->steer_via))
					continue;
				if ((ar = nl_route_add_prefix(g_sk, split[i], 1, &desired->steer_via)) < 0)
					hadc_warn("executor: adding steering route %s/1 via %s failed: %s",
					    dstbuf, viabuf, nl_geterror(ar));
				else
					hadc_info("executor: added steering route %s/1 via %s (reason=%s)",
					    dstbuf, viabuf, reason);
			}
			n_vips = vip_splits(desired, &desired->steer_via, vips, VIP_SPLIT_MAX);
			for (size_t i = 0; i < n_vips; i++) {
				char dstbuf[INET_ADDRSTRLEN];
				hadc_ipv4_format(vips[i].net, dstbuf, sizeof(dstbuf));
				if (find_prefix_route(rcache, &vips[i].net, vips[i].plen, &desired->steer_via))
					continue;
				if ((ar = nl_route_add_prefix(g_sk, &vips[i].net, vips[i].plen,
				        &desired->steer_via)) < 0)
					hadc_warn("executor: adding steering route %s/%u via %s failed: %s",
					    dstbuf, vips[i].plen, viabuf, nl_geterror(ar));
				else
					hadc_info("executor: added steering route %s/%u via %s (reason=%s)",
					    dstbuf, vips[i].plen, viabuf, reason);
			}
		} else if (prev && prev->steer_via.s_addr) {
			char viabuf[INET_ADDRSTRLEN];
			hadc_ipv4_format(prev->steer_via, viabuf, sizeof(viabuf));
			for (size_t i = 0; i < 2; i++) {
				char dstbuf[INET_ADDRSTRLEN];
				hadc_ipv4_format(*split[i], dstbuf, sizeof(dstbuf));
				sroute = find_prefix_route(rcache, split[i], 1, &prev->steer_via);
				if (!sroute)
					continue;
				if ((ar = rtnl_route_delete(g_sk, sroute, 0)) < 0)
					hadc_warn("executor: deleting steering route %s/1 via %s failed: %s",
					    dstbuf, viabuf, nl_geterror(ar));
				else
					hadc_info("executor: removed steering route %s/1 via %s (reason=%s)",
					    dstbuf, viabuf, reason);
			}
			n_vips = vip_splits(prev, &prev->steer_via, vips, VIP_SPLIT_MAX);
			for (size_t i = 0; i < n_vips; i++) {
				char dstbuf[INET_ADDRSTRLEN];
				hadc_ipv4_format(vips[i].net, dstbuf, sizeof(dstbuf));
				sroute = find_prefix_route(rcache, &vips[i].net, vips[i].plen, &prev->steer_via);
				if (!sroute)
					continue;
				if ((ar = rtnl_route_delete(g_sk, sroute, 0)) < 0)
					hadc_warn("executor: deleting steering route %s/%u via %s failed: %s",
					    dstbuf, vips[i].plen, viabuf, nl_geterror(ar));
				else
					hadc_info("executor: removed steering route %s/%u via %s (reason=%s)",
					    dstbuf, vips[i].plen, viabuf, reason);
			}
		}
	}

	if (desired->link_state == 2 && (rtnl_link_get_flags(link) & IFF_UP)) {
		if ((ar = nl_link_set_state(g_sk, ifindex, false)) < 0)
			hadc_warn("executor: bringing link %s down failed: %s",
			    desired->interface, nl_geterror(ar));
		else
			hadc_info("executor: link %s brought down (reason=%s)",
			    desired->interface, reason);
	}

	apply_slave_nft_block(desired->interface, desired->slave_nft_block, reason);

	apply_demote_hold_nft(ctx, desired, prev, reason);

	if (ctx->conf.apply.dns_hook[0]) {
		char *argv[2] = { ctx->conf.apply.dns_hook, NULL };
		run_hook(argv, prev, desired, reason);
	}

	/* ddclient: one-shot DDNS update, master-only (the node that owns the public
	 * IP), only when the applied address changed. ddclient dedups against its own
	 * cache, so a reboot that lands on the same IP is a no-op; a node that comes
	 * up with a different IP updates. */
	if (!fatal && (ctx->role == HADC_ROLE_MASTER || ctx->role == HADC_ROLE_PROMOTING) && ctx->conf.apply.ddclient[0] && desired->present &&
	    (!prev || !prev->present || prev->address.s_addr != desired->address.s_addr)) {
		char *argv[4] = { ctx->conf.apply.ddclient, (char *)"-daemon=0", (char *)"-syslog",
			NULL };
		run_hook(argv, prev, desired, reason);
	}

out:
	if (!fatal) {
		apply_disable_ipv6(ctx);
		apply_rp_filter(ctx);
		g_applied = *desired;
		g_applied_valid = true;
	}
	nl_cache_drop(&lcache);
	nl_cache_drop(&acache);
	nl_cache_drop(&rcache);
	return fatal;
}

/* Gratuitous ARP: an ARP request with sender and target both set to the VIP,
 * broadcast on the interface, so the switch refreshes its CAM/fdb entry. */
struct garp_pkt {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint32_t spa;
    uint8_t tha[6];
    uint32_t tpa;
} __attribute__((packed));

static int garp_announce(const char *ifname, const struct in_addr *ip)
{
    struct ifreq ifr;
    struct sockaddr_ll sa;
    struct garp_pkt p;
    uint8_t mac[6];
    int ctl, s, ifindex, rc = -1;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    ctl = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctl < 0) {
        hadc_warn("executor: gratuitous ARP control socket failed: %s", strerror(errno));
        return -1;
    }
    if (ioctl(ctl, SIOCGIFINDEX, &ifr) != 0) {
        hadc_warn("executor: cluster interface %s not found for gratuitous ARP: %s", ifname,
                  strerror(errno));
        close(ctl);
        return -1;
    }
    ifindex = ifr.ifr_ifindex;
    if (ioctl(ctl, SIOCGIFHWADDR, &ifr) != 0) {
        hadc_warn("executor: cannot read MAC of %s for gratuitous ARP: %s", ifname,
                  strerror(errno));
        close(ctl);
        return -1;
    }
    close(ctl);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, sizeof(mac));

    s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (s < 0) {
        hadc_warn("executor: gratuitous ARP packet socket failed: %s", strerror(errno));
        return -1;
    }
    memset(&p, 0, sizeof(p));
    memset(p.dst, 0xff, sizeof(p.dst));
    memcpy(p.src, mac, sizeof(mac));
    p.ethertype = htons(ETH_P_ARP);
    p.htype = htons(ARPHRD_ETHER);
    p.ptype = htons(ETH_P_IP);
    p.hlen = sizeof(mac);
    p.plen = 4;
    p.oper = htons(ARPOP_REQUEST); /* gratuitous: request for our own address */
    memcpy(p.sha, mac, sizeof(mac));
    p.spa = ip->s_addr;
    p.tpa = ip->s_addr;

    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = ifindex;
    if (sendto(s, &p, sizeof(p), 0, (struct sockaddr *)&sa, sizeof(sa)) == (ssize_t)sizeof(p))
        rc = 0;
    else
        hadc_warn("executor: gratuitous ARP send on %s failed: %s", ifname, strerror(errno));
    close(s);
    return rc;
}

int hadc_executor_announce_cluster(hadc_ctx_t *ctx)
{
    int announced = 0;

    if (!ctx->conf.apply.announce_gratuitous)
        return 0;
    uint32_t duration_ms = ctx->conf.apply.announce_gratuitous_duration_ms;
    uint64_t deadline = (uint64_t)hadc_now_ms() + duration_ms;
    for (;;) {
        int pass = 0;
        for (size_t i = 0; i < ctx->conf.cluster.n_ifaces; i++) {
            const hadc_cluster_if_t *ci = &ctx->conf.cluster.ifaces[i];
            for (size_t j = 0; j < ci->n_addrs; j++)
                if (garp_announce(ci->interface, &ci->addrs[j].address) == 0)
                    pass++;
        }
        if (pass > announced)
            announced = pass;
        if (duration_ms == 0)
            break;
        uint64_t now = (uint64_t)hadc_now_ms();
        if (now >= deadline)
            break;
        usleep(2000);
    }
    if (announced)
        hadc_info("executor: announced %d cluster address(es) with gratuitous ARP (burst %ums)",
                  announced, duration_ms);
    return 0;
}

/* Block/unblock all egress on an interface via nft netdev hook while keeping
 * the link up (slave isolation alternative to bringing the link down). */
/* Whitelist for interface names embedded in nft CLI arguments (the procfs
 * strpbrk guard above rejects dots, which are normal in VLAN names and safe
 * here: the name sits inside shell single quotes and nft's own quoting). */
static bool nft_iface_ok(const char *ifname)
{
	if (!ifname[0])
		return false;
	for (const char *p = ifname; *p; p++) {
		unsigned char c = (unsigned char)*p;
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
			return false;
	}
	return true;
}

static void nft_chain_name(const char *ifname, char *out, size_t outsz)
{
	size_t j = 0;
	for (size_t i = 0; ifname[i] && j + 1 < outsz; i++) {
		unsigned char c = (unsigned char)ifname[i];
		out[j++] = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		           (c >= '0' && c <= '9') || c == '_'
		               ? (char)c
		               : '_';
	}
	out[j] = '\0';
}

static void apply_slave_nft_block(const char *ifname, bool block, const char *reason)
{
	char chain[HADC_IFNAME_MAX * 2 + 16];
	char cmd[512];
	int rc;

	if (!ifname[0])
		return;
	nft_chain_name(ifname, chain, sizeof(chain));

	if (block) {
		snprintf(cmd, sizeof(cmd),
		    "nft 'add table netdev ha_dhcpc' 2>/dev/null; "
		    "nft 'delete chain netdev ha_dhcpc %s' 2>/dev/null; "
		    "nft 'add chain netdev ha_dhcpc %s { type filter hook egress device \"%s\" priority 0; policy drop; }'",
		    chain, chain, ifname);
		rc = system(cmd);
		if (rc == 0)
			hadc_info("executor: nft egress block enabled on %s (reason=%s)", ifname, reason);
		else
			hadc_warn("executor: enabling nft egress block on %s failed (rc=%d, reason=%s)",
			    ifname, rc, reason);
	} else {
		snprintf(cmd, sizeof(cmd),
		    "nft 'delete chain netdev ha_dhcpc %s' 2>/dev/null; "
		    "nft 'delete table netdev ha_dhcpc' 2>/dev/null", chain);
		rc = system(cmd);
		if (rc == 0)
			hadc_dbg("executor: nft egress block cleared for %s (reason=%s)", ifname, reason);
		else
			hadc_dbg("executor: nft egress block clear for %s returned rc=%d (reason=%s)",
			    ifname, rc, reason);
	}
}

/* Seamless takeover, demoting-hold scoping (plan SEAMLESS_TAKEOVER.md):
 *  - netdev egress chain per VIP interface dropping ARP replies whose sender IP
 *    is a VIP (the demoting node keeps VIPs assigned during the hold but must
 *    not claim them; the new master's GARPs are requests and pass untouched);
 *  - ip-family output chain dropping locally-originated traffic sourced from a
 *    VIP (forwarding only, no VIP-source traffic during the hold);
 *  - NAT-bypass chains at prerouting/postrouting priority -300 (before the
 *    firewall's conntrack/nat hooks) when NOTRACK is enabled: a fib rule
 *    (daddr . iif lookup, so policy routing is respected) untracks exactly the
 *    steered traffic whose FIB lookup exits via a fabric interface, plus the
 *    return direction entering the fabric. NOTRACK must live here (prerouting):
 *    state is created before the forward hook and SNAT runs after it, so a
 *    NOTRACK rule on the outgoing interface alone would not bypass anything.
 *    When a mark is configured it is set before the verdicts (it survives
 *    untracking) as the firewall's scoping handle; the firewall must accept
 *    untracked steered traffic in forward (ct state untracked accept) — see
 *    SEAMLESS_FIREWALL_HOWTO.md.
 * Scoped to the configured VIP set, active only while steering; reconciled on
 * transitions only. */
#define HADC_TAKEOVER_NFT_TABLE "ha_dhcpc_tk"

static void demote_hold_signature(const hadc_desired_t *d, char *out, size_t outsz)
{
	size_t n;

	if (!d) {
		snprintf(out, outsz, "none");
		return;
	}
	n = snprintf(out, outsz, "%d|%u|%d|", d->vip_hold_suppress ? 1 : 0,
	    (unsigned)d->nat_bypass_mark, d->nat_bypass_notrack ? 1 : 0);
	for (size_t i = 0; i < d->n_cluster_ifaces && n < outsz - 1; i++) {
		const hadc_cluster_if_t *ci = &d->cluster_ifaces[i];
		for (size_t j = 0; j < ci->n_addrs && n < outsz - 40; j++) {
			char abuf[INET_ADDRSTRLEN];
			hadc_ipv4_format(ci->addrs[j].address, abuf, sizeof(abuf));
			n += (size_t)snprintf(out + n, outsz - n, "%s%s/%u", j ? " " : "a=",
			    abuf, ci->addrs[j].prefixlen);
		}
		if (n < outsz - 1)
			n += (size_t)snprintf(out + n, outsz - n, ";");
	}
}

static int nft_run(const char *cmd, const char *reason, bool enable)
{
	int rc = system(cmd);
	if (rc != 0 && enable)
		hadc_warn("executor: takeover nft failed (rc=%d, cmd=%s, reason=%s)", rc, cmd, reason);
	else if (rc != 0)
		hadc_dbg("executor: takeover nft cleanup rc=%d (cmd=%s, reason=%s)", rc, cmd, reason);
	return rc;
}

static void apply_demote_hold_nft(hadc_ctx_t *ctx, const hadc_desired_t *desired,
    const hadc_desired_t *prev, const char *reason)
{
	char sig_new[6144], sig_old[6144];
	char cmd[512], chain[80], san[64];
	bool was_active, is_active;

	demote_hold_signature(desired, sig_new, sizeof(sig_new));
	demote_hold_signature(prev, sig_old, sizeof(sig_old));
	if (prev && !strcmp(sig_new, sig_old))
		return; /* no transition, no delta */

	was_active = prev && (prev->vip_hold_suppress || prev->nat_bypass_mark ||
	    prev->nat_bypass_notrack);
	is_active = desired->vip_hold_suppress || desired->nat_bypass_mark ||
	    desired->nat_bypass_notrack;
	if (!was_active && !is_active)
		return;

	/* Tear down the previous scoping first (only our own chains; the netdev
	 * table is shared with the slave egress block lifecycle). */
	if (was_active) {
		if (prev->vip_hold_suppress) {
			for (size_t i = 0; i < prev->n_cluster_ifaces; i++) {
				if (!prev->cluster_ifaces[i].n_addrs)
					continue;
				nft_chain_name(prev->cluster_ifaces[i].interface, san, sizeof(san));
				snprintf(cmd, sizeof(cmd), "nft 'delete chain netdev ha_dhcpc ar_%s' 2>/dev/null", san);
				nft_run(cmd, reason, false);
			}
			nft_run("nft 'delete chain ip " HADC_TAKEOVER_NFT_TABLE " out' 2>/dev/null", reason, false);
		}
		if (prev->nat_bypass_mark || prev->nat_bypass_notrack) {
			nft_run("nft 'delete chain ip " HADC_TAKEOVER_NFT_TABLE " pre' 2>/dev/null", reason, false);
			nft_run("nft 'delete chain ip " HADC_TAKEOVER_NFT_TABLE " post' 2>/dev/null", reason, false);
		}
		if (!is_active)
			nft_run("nft 'delete table ip " HADC_TAKEOVER_NFT_TABLE "' 2>/dev/null", reason, false);
	}

	if (!is_active) {
		hadc_dbg("executor: takeover ARP/NAT scoping cleared (reason=%s)", reason);
		return;
	}

	if (desired->vip_hold_suppress) {
		for (size_t i = 0; i < desired->n_cluster_ifaces; i++) {
			const hadc_cluster_if_t *ci = &desired->cluster_ifaces[i];
			if (!ci->n_addrs || !nft_iface_ok(ci->interface))
				continue;
			nft_chain_name(ci->interface, san, sizeof(san));
			snprintf(chain, sizeof(chain), "ar_%s", san);
			snprintf(cmd, sizeof(cmd),
			    "nft 'add table netdev ha_dhcpc' 2>/dev/null; "
			    "nft 'delete chain netdev ha_dhcpc %s' 2>/dev/null; "
			    "nft 'add chain netdev ha_dhcpc %s { type filter hook egress device \"%s\" priority 0; policy accept; }'",
			    chain, chain, ci->interface);
			nft_run(cmd, reason, true);
			for (size_t j = 0; j < ci->n_addrs; j++) {
				char abuf[INET_ADDRSTRLEN];
				hadc_ipv4_format(ci->addrs[j].address, abuf, sizeof(abuf));
				snprintf(cmd, sizeof(cmd),
				    "nft 'add rule netdev ha_dhcpc %s ether type arp arp operation reply arp saddr ip %s drop'",
				    chain, abuf);
				nft_run(cmd, reason, true);
			}
		}
		nft_run("nft 'add table ip " HADC_TAKEOVER_NFT_TABLE "' 2>/dev/null; "
		          "nft 'delete chain ip " HADC_TAKEOVER_NFT_TABLE " out' 2>/dev/null; "
		          "nft 'add chain ip " HADC_TAKEOVER_NFT_TABLE " out { type filter hook output priority -150; policy accept; }'",
		          reason, true);
		for (size_t i = 0; i < desired->n_cluster_ifaces; i++) {
			const hadc_cluster_if_t *ci = &desired->cluster_ifaces[i];
			for (size_t j = 0; j < ci->n_addrs; j++) {
				char abuf[INET_ADDRSTRLEN];
				hadc_ipv4_format(ci->addrs[j].address, abuf, sizeof(abuf));
				snprintf(cmd, sizeof(cmd),
				    "nft 'add rule ip " HADC_TAKEOVER_NFT_TABLE " out ip saddr %s drop'",
				    abuf);
				nft_run(cmd, reason, true);
			}
		}
		hadc_info("executor: takeover VIP ARP/source scoping active (reason=%s)", reason);
	}

	if (desired->nat_bypass_mark || desired->nat_bypass_notrack) {
		uint32_t m = desired->nat_bypass_mark;
		nft_run("nft 'add table ip " HADC_TAKEOVER_NFT_TABLE "' 2>/dev/null; "
		          "nft 'delete chain ip " HADC_TAKEOVER_NFT_TABLE " pre' 2>/dev/null; "
		          "nft 'delete chain ip " HADC_TAKEOVER_NFT_TABLE " post' 2>/dev/null; "
		          "nft 'add chain ip " HADC_TAKEOVER_NFT_TABLE " pre { type filter hook prerouting priority -300; policy accept; }'; "
		          "nft 'add chain ip " HADC_TAKEOVER_NFT_TABLE " post { type filter hook postrouting priority -300; policy accept; }'",
		          reason, true);
		/* Mark first (it must survive untracking so the firewall can still
		 * match it), then the NOTRACK verdicts. NOTRACK here (prerouting,
		 * before conntrack) is what keeps state and NAT off this node: the
		 * fib rule untracks exactly the packets whose FIB lookup (iif included
		 * so policy routing is respected) exits via a fabric interface — the
		 * steered transit — and the iifname rule untracks the return direction
		 * entering the fabric. The platform firewall must accept untracked
		 * steered traffic in forward (ct state untracked accept). */
		{
			const char *in_ifaces[1 + HADC_CLUSTER_IF_MAX + HADC_CLUSTER_IF_MAX];
			size_t n_in = 0;
			if (m != 0) {
				if (ctx->conf.interface[0])
					in_ifaces[n_in++] = ctx->conf.interface;
				for (size_t i = 0; i < ctx->conf.cluster.n_ifaces && n_in < sizeof(in_ifaces) / sizeof(in_ifaces[0]); i++)
					if (ctx->conf.cluster.ifaces[i].interface[0])
						in_ifaces[n_in++] = ctx->conf.cluster.ifaces[i].interface;
				for (size_t i = 0; i < ctx->conf.ospf.n_interfaces && n_in < sizeof(in_ifaces) / sizeof(in_ifaces[0]); i++)
					if (ctx->conf.ospf.interfaces[i][0])
						in_ifaces[n_in++] = ctx->conf.ospf.interfaces[i];
				for (size_t i = 0; i < n_in; i++) {
					if (!nft_iface_ok(in_ifaces[i]))
						continue;
					snprintf(cmd, sizeof(cmd),
					    "nft 'add rule ip " HADC_TAKEOVER_NFT_TABLE " pre iifname \"%s\" meta mark set 0x%x'",
					    in_ifaces[i], m);
					nft_run(cmd, reason, true);
					snprintf(cmd, sizeof(cmd),
					    "nft 'add rule ip " HADC_TAKEOVER_NFT_TABLE " post oifname \"%s\" meta mark set 0x%x'",
					    in_ifaces[i], m);
					nft_run(cmd, reason, true);
				}
			}
			if (desired->nat_bypass_notrack) {
				for (size_t i = 0; i < ctx->conf.ospf.n_interfaces; i++) {
					const char *f = ctx->conf.ospf.interfaces[i];
					if (!nft_iface_ok(f))
						continue;
					snprintf(cmd, sizeof(cmd),
					    "nft 'add rule ip " HADC_TAKEOVER_NFT_TABLE " pre fib daddr . iif oifname \"%s\" notrack'",
					    f);
					nft_run(cmd, reason, true);
					snprintf(cmd, sizeof(cmd),
					    "nft 'add rule ip " HADC_TAKEOVER_NFT_TABLE " pre iifname \"%s\" notrack'",
					    f);
					nft_run(cmd, reason, true);
				}
			}
		}
		hadc_info("executor: takeover NAT-bypass active (mark 0x%x, notrack %s; "
		          "zone-based firewalls must accept marked/untracked steered traffic; "
		          "reason=%s)", m, desired->nat_bypass_notrack ? "on" : "off", reason);
	}
}

void hadc_executor_clear_slave_isolation(const char *ifname)
{
	apply_slave_nft_block(ifname, false, "SHUTDOWN");
}

/* Hand-built RTM_SETLINK, matching the addr/route helpers above. */
static int nl_link_set_state(struct nl_sock *sk, int ifindex, bool up)
{
	struct nl_msg *m = nlmsg_alloc_simple(RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK);
	struct ifinfomsg *ifi;

	if (!m)
		return -1;
	ifi = (struct ifinfomsg *) nlmsg_reserve(m, sizeof(*ifi), NLA_ALIGNTO);
	if (!ifi) {
		nlmsg_free(m);
		return -1;
	}
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;
	ifi->ifi_flags = up ? IFF_UP : 0;
	ifi->ifi_change = IFF_UP;
	return nl_send_sync(sk, m); /* consumes m */
}

int hadc_executor_link_up(const char *ifname)
{
    struct nl_cache *lcache = NULL;
    struct rtnl_link *link;
    int rc = 0;

    hadc_maint_lock();
    if (!g_sk) {
        hadc_warn("executor: netlink socket not open");
        hadc_maint_unlock();
        return -1;
    }
    if (hadc_nl_alloc_caches(g_sk, &lcache, NULL, NULL, NULL) < 0 || !lcache) {
        hadc_warn("executor: netlink cache dump failed");
        hadc_maint_unlock();
        return -1;
    }
    link = rtnl_link_get_by_name(lcache, ifname);
    if (!link) {
        hadc_warn("executor: interface %s not found", ifname);
        nl_cache_drop(&lcache);
        hadc_maint_unlock();
        return -1;
    }
    if (!(rtnl_link_get_flags(link) & IFF_UP)) {
        if ((rc = nl_link_set_state(g_sk, rtnl_link_get_ifindex(link), true)) < 0)
            hadc_warn("executor: bringing link %s up failed: %s", ifname, nl_geterror(rc));
        else
            hadc_info("executor: link %s brought up", ifname);
    }
    nl_cache_drop(&lcache);
    hadc_maint_unlock();
    return rc;
}
