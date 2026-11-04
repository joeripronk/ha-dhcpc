/* Executor: declarative desired state + idempotent netlink reconcile (plan §3).
 * Adds/removes only on delta; addresses and routes we did not apply ourselves
 * (per-node sync secondaries) are left alone. dhclient-script compatible
 * dns_hook dispatch with the standard reasons. */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <jansson.h>
#include <linux/rtnetlink.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/addr.h>
#include <netlink/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/log.h"
#include "internal.h"

static struct nl_sock *g_sk;

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
	(void)ctx;
	return 0;
}

/* Canonical desired-state text for hashing: stable field order. */
static void canonical_desired(const hadc_desired_t *d, char *out, size_t outsz)
{
    json_t *o = json_pack(
        "{s:s, s:b, s:s, s:I, s:s, s:s, s:s}", "interface", d->interface, "present", d->present,
        "address", inet_ntoa(d->address), "prefixlen", (json_int_t)d->prefixlen, "gateway",
        inet_ntoa(d->gateway), "dns", "", "routes", d->add_routes ? "yes" : "no");
    json_t *dns = json_array();
    for (size_t i = 0; i < d->n_dns; i++)
        json_array_append_new(dns, json_string(inet_ntoa(d->dns[i])));
    json_object_set_new(o, "dns", dns);
    char *txt = json_dumps(o, JSON_PRESERVE_ORDER | JSON_COMPACT);
    snprintf(out, outsz, "%s", txt ? txt : "");
    free(txt);
    json_decref(o);
}

void hadc_executor_desired(hadc_ctx_t *ctx, const hadc_lease_t *lease, hadc_desired_t *out)
{
    memset(out, 0, sizeof(*out));
    snprintf(out->interface, sizeof(out->interface), "%s", ctx->conf.interface);
    out->add_routes = ctx->conf.apply.routes;

    if (lease->state == HADC_LEASE_NONE) {
        out->present = false;
    } else {
        out->present = true;
        out->address = lease->address;
        out->prefixlen = (unsigned)__builtin_popcount(ntohl(lease->netmask.s_addr));
        out->gateway = lease->gateway;
        out->n_dns = lease->n_dns;
        for (size_t i = 0; i < lease->n_dns; i++)
            out->dns[i] = lease->dns[i];
    }
    char canon[1024];
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

struct route_match {
	const struct in_addr *gw;
	struct rtnl_route *found;
};

static void route_match_cb(struct nl_object *obj, void *p)
{
	struct route_match *m = p;
	struct rtnl_route *r = (struct rtnl_route *)obj;
	struct nl_addr *dst = rtnl_route_get_dst(r);
	static const struct in_addr any;
	int i;

	if (rtnl_route_get_type(r) != RTN_UNICAST)
		return;
	if (!dst || nl_addr_get_family(dst) != AF_INET || nl_addr_get_len(dst) != 4)
		return;
	if (nl_addr_get_prefixlen(dst) != 0 ||
	    memcmp(nl_addr_get_binary_addr(dst), &any, 4) != 0)
		return;
	for (i = 0; i < rtnl_route_get_nnexthops(r); i++) {
		struct nl_addr *gw = rtnl_route_nh_get_gateway(rtnl_route_nexthop_n(r, i));

		if (gw && nl_addr_get_len(gw) == 4 &&
		    memcmp(nl_addr_get_binary_addr(gw), m->gw, 4) == 0) {
			m->found = r;
			return;
		}
	}
}

static struct rtnl_route *find_default(struct nl_cache *cache, const struct in_addr *gw)
{
	struct route_match m = { gw, NULL };

	nl_cache_foreach(cache, route_match_cb, &m);
	return m.found;
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

	mask.s_addr = d->prefixlen <= 32 ? htonl(~(0xffffffffu >> d->prefixlen)) : 0;
	snprintf(e_reason, sizeof(e_reason), "reason=%s", reason);
	snprintf(e_if, sizeof(e_if), "interface=%s", d->interface);
	snprintf(e_newip, sizeof(e_newip), "new_ip_address=%s",
	    d->present ? inet_ntoa(d->address) : "");
	snprintf(e_oldip, sizeof(e_oldip), "old_ip_address=%s",
	    prev && prev->present ? inet_ntoa(prev->address) : "");
	snprintf(e_mask, sizeof(e_mask), "new_mask=%s",
	    d->present ? inet_ntoa(mask) : "");
	snprintf(e_gw, sizeof(e_gw), "new_routers=%s",
	    d->gateway.s_addr ? inet_ntoa(d->gateway) : "");
	pos = 0;
	for (size_t i = 0; i < d->n_dns && pos < sizeof(e_dns) - 16; i++)
		pos += snprintf(e_dns + pos, sizeof(e_dns) - pos, "%s%s", i ? " " : "",
		    inet_ntoa(d->dns[i]));
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
		uint32_t mask = ~(0xffffffffu >> plen);
		struct in_addr bc;
		bc.s_addr = htonl((ntohl(ip->s_addr) & mask) | ~mask);
		nla_put(m, IFA_BROADCAST, 4, &bc);
	}
	nla_put(m, IFA_LOCAL, 4, ip);
	nla_put(m, IFA_ADDRESS, 4, ip);
	return nl_send_sync(sk, m); /* consumes m */
}

static int nl_route_add_default(struct nl_sock *sk, int ifindex, const struct in_addr *gw)
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
	rt->rtm_table = RT_TABLE_MAIN;
	rt->rtm_protocol = RTPROT_BOOT;
	rt->rtm_scope = RT_SCOPE_UNIVERSE;
	rt->rtm_type = RTN_UNICAST;
	nla_put(m, RTA_GATEWAY, 4, gw);
	nla_put(m, RTA_OIF, 4, &ifindex);
	return nl_send_sync(sk, m); /* consumes m */
}

int hadc_executor_apply(hadc_ctx_t *ctx, const hadc_desired_t *desired, const char *reason)
{
	struct nl_cache *lcache = NULL, *acache = NULL, *rcache = NULL;
	struct rtnl_link *link;
	struct rtnl_addr *stale;
	struct rtnl_route *sroute;
	const hadc_desired_t *prev = g_applied_valid ? &g_applied : NULL;
	int ifindex, rc = 0;

	if (g_applied_valid && !memcmp(g_applied.config_hash, desired->config_hash,
	    sizeof(g_applied.config_hash))) {
		hadc_dbg("executor: desired state already applied (no delta, reason=%s)", reason);
		return 0;
	}
	if (!g_sk) {
		hadc_err("executor: netlink socket not open");
		return -1;
	}
	hadc_info("executor: apply delta reason=%s interface=%s present=%d hash=%02x%02x%02x%02x",
	    reason, desired->interface, desired->present, desired->config_hash[0],
	    desired->config_hash[1], desired->config_hash[2], desired->config_hash[3]);

	if (rtnl_link_alloc_cache(g_sk, AF_UNSPEC, &lcache) < 0 ||
	    rtnl_addr_alloc_cache(g_sk, &acache) < 0 ||
	    rtnl_route_alloc_cache(g_sk, AF_INET, 0, &rcache) < 0) {
		hadc_warn("executor: netlink cache dump failed");
		rc = -1;
		goto out;
	}
	link = rtnl_link_get_by_name(lcache, desired->interface);
	if (!link) {
		hadc_warn("executor: interface %s not found", desired->interface);
		rc = -1;
		goto out;
	}
	ifindex = rtnl_link_get_ifindex(link);

	/* Address reconcile: remove only what we applied, add the desired one;
	   addresses we never applied (e.g. per-node sync secondaries) stay. */
	if (prev && prev->present &&
	    (!desired->present || desired->address.s_addr != prev->address.s_addr ||
	    desired->prefixlen != prev->prefixlen)) {
		stale = find_addr(acache, ifindex, &prev->address, prev->prefixlen);
		if (stale) {
			if ((rc = rtnl_addr_delete(g_sk, stale, 0)) < 0)
				hadc_warn("executor: deleting address %s/%u failed: %s",
				    inet_ntoa(prev->address), prev->prefixlen,
				    nl_geterror(rc));
			else
				hadc_info("executor: removed address %s/%u from %s (reason=%s)",
				    inet_ntoa(prev->address), prev->prefixlen,
				    desired->interface, reason);
		}
	}
	if (desired->present) {
		struct rtnl_addr *cur = find_addr(acache, ifindex, &desired->address, -1);
		if (cur && (unsigned)rtnl_addr_get_prefixlen(cur) != desired->prefixlen) {
			/* Same address, wrong prefix (e.g. left over by an older
			   build): replace it, it is our lease address. */
			if ((rc = rtnl_addr_delete(g_sk, cur, 0)) < 0)
				hadc_warn("executor: replacing address %s/%u failed: %s",
				    inet_ntoa(desired->address),
				    (unsigned)rtnl_addr_get_prefixlen(cur), nl_geterror(rc));
			else
				hadc_info("executor: replaced address %s/%u on %s (reason=%s)",
				    inet_ntoa(desired->address),
				    (unsigned)rtnl_addr_get_prefixlen(cur),
				    desired->interface, reason);
			cur = NULL;
		}
		if (!cur) {
			if ((rc = nl_addr_add(g_sk, ifindex, &desired->address,
			    desired->prefixlen)) < 0)
				hadc_warn("executor: adding address %s/%u failed: %s",
				    inet_ntoa(desired->address), desired->prefixlen,
				    nl_geterror(rc));
			else
				hadc_info("executor: added address %s/%u on %s (reason=%s)",
				    inet_ntoa(desired->address), desired->prefixlen,
				    desired->interface, reason);
		} else {
			hadc_dbg("executor: address %s/%u already present on %s",
			    inet_ntoa(desired->address), desired->prefixlen,
			    desired->interface);
		}
	}

	if (desired->add_routes) {
		if (prev && prev->gateway.s_addr &&
		    prev->gateway.s_addr != desired->gateway.s_addr) {
			sroute = find_default(rcache, &prev->gateway);
			if (sroute) {
				if ((rc = rtnl_route_delete(g_sk, sroute, 0)) < 0)
					hadc_warn("executor: deleting default route via %s failed: %s",
					    inet_ntoa(prev->gateway), nl_geterror(rc));
				else
					hadc_info("executor: removed default route via %s (reason=%s)",
					    inet_ntoa(prev->gateway), reason);
			}
		}
		if (desired->gateway.s_addr && !find_default(rcache, &desired->gateway)) {
			if ((rc = nl_route_add_default(g_sk, ifindex, &desired->gateway)) < 0)
				hadc_warn("executor: adding default route via %s failed: %s",
				    inet_ntoa(desired->gateway), nl_geterror(rc));
			else
				hadc_info("executor: added default route via %s on %s (reason=%s)",
				    inet_ntoa(desired->gateway), desired->interface, reason);
		} else if (desired->gateway.s_addr) {
			hadc_dbg("executor: default route via %s already present",
			    inet_ntoa(desired->gateway));
		}
	}

	if (ctx->conf.apply.dns_hook[0]) {
		char *argv[2] = { ctx->conf.apply.dns_hook, NULL };
		run_hook(argv, prev, desired, reason);
	}

	/* ddclient: one-shot DDNS update, master-only (the node that owns the public
	 * IP), only when the applied address changed. ddclient dedups against its own
	 * cache, so a reboot that lands on the same IP is a no-op; a node that comes
	 * up with a different IP updates. */
	if (!rc && ctx->role == HADC_ROLE_MASTER && ctx->conf.apply.ddclient[0] && desired->present &&
	    (!prev || !prev->present || prev->address.s_addr != desired->address.s_addr)) {
		char *argv[4] = { ctx->conf.apply.ddclient, (char *)"-daemon=0", (char *)"-syslog",
			NULL };
		run_hook(argv, prev, desired, reason);
	}

out:
	if (!rc) {
		g_applied = *desired;
		g_applied_valid = true;
	}
	if (lcache)
		nl_cache_put(lcache);
	if (acache)
		nl_cache_put(acache);
	if (rcache)
		nl_cache_put(rcache);
	return rc;
}
