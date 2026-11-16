/* Inter-cluster routing (edge-only, local-prefix origination). Modular core:
 * compute desired advertisement/accept state from ha-dhcpc role+lease+health,
 * select fabric-learned backup defaults from attributed candidates, apply through
 * a backend interface (stub/no-op here), and expose status. Backup routes and
 * fabric-learned defaults are never published. */
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/log.h"
#include "ha-dhcpc/routing.h"
#include "internal.h"
#include "ospf.h"

#define HADC_ROUTING_MAX_PREFIXES 64
#define HADC_ROUTING_MAX_INSTALLED 128

typedef struct {
    struct in_addr prefix;
    unsigned prefixlen;
    char ifname[HADC_IFNAME_MAX];
} hadc_routing_prefix_t;

typedef struct {
    struct in_addr prefix;
    unsigned prefixlen;
    struct in_addr nexthop;
    bool valid;
} hadc_routing_installed_t;

typedef struct {
    bool publish_public_ip32;
    bool publish_default_route; /* primary healthy path only, never backup */
    bool accept_default_route;
    bool using_backup_path;
    bool local_master_up;
    bool local_working_default;
    struct in_addr public_ip32;
    struct in_addr backup_gw; /* selected fabric-learned default (backup path only) */
    char backup_scope[24];
    char backup_origin[HADC_ROUTING_ORIGIN_MAX];
    char reason[64];
    char backend[16];
    char router_id[INET_ADDRSTRLEN];
    bool advertised_public_ip32;
    bool advertised_default_route;
    bool want_advertised_public_ip32;
    bool want_advertised_default_route;
    uint64_t backup_hold_until_ms; /* delay slave backup routes until master promoted + wait */
    char last_seen_master[HADC_NODE_ID_MAX];
    hadc_routing_default_candidate_t local_cand; /* from cluster/heartbeat info */
    hadc_routing_default_candidate_t remote_cands[HADC_ROUTING_MAX_CANDIDATES];
    size_t n_remote_cands;
    hadc_routing_prefix_t want_prefixes[HADC_ROUTING_MAX_PREFIXES];
    size_t n_want_prefixes;

    hadc_routing_installed_t installed[HADC_ROUTING_MAX_INSTALLED];
    size_t n_installed;

} hadc_routing_state_t;

static hadc_routing_state_t g_rs;

static bool local_master_alive(hadc_ctx_t *ctx)
{
    if (ctx->role == HADC_ROLE_MASTER || ctx->role == HADC_ROLE_PROMOTING)
        return true;
    if (!ctx->conf.designated_master[0])
        return false;
    if (!strcmp(ctx->conf.designated_master, ctx->conf.self))
        return true;
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        if (!strcmp(ctx->conf.members[i].id, ctx->conf.designated_master))
            return ctx->peers[i].alive;
    }
    return false;
}

static bool local_working_default_path(hadc_ctx_t *ctx)
{
    /* Primary healthy local default path available (not on backup). Local
     * working default always takes precedence over fabric-learned defaults. */
    if (ctx->role == HADC_ROLE_MASTER || ctx->role == HADC_ROLE_PROMOTING) {
        return ctx->lease.address.s_addr != 0 && ctx->lease.gateway.s_addr != 0 &&
               !hadc_gwping_unreachable() &&
               (ctx->lease.state == HADC_LEASE_BOUND ||
                ctx->lease.state == HADC_LEASE_RENEW ||
                ctx->lease.state == HADC_LEASE_REBIND);
    }
    /* Slaves have no primary DHCP default route of their own. */
    return false;
}

static bool on_backup_path(hadc_ctx_t *ctx)
{
    if (ctx->role == HADC_ROLE_MASTER || ctx->role == HADC_ROLE_PROMOTING)
        return hadc_gwping_unreachable() || ctx->lease.address.s_addr == 0;
    return ctx->role == HADC_ROLE_SLAVE;
}

static const char *scope_name(hadc_route_scope_t scope)
{
    switch (scope) {
    case HADC_ROUTE_SCOPE_LOCAL_MASTER:
        return "local_master";
    case HADC_ROUTE_SCOPE_REMOTE_MASTER:
        return "remote_master";
    default:
        return "unknown";
    }
}

/* Resolve attribution from cluster information (heartbeat/member state):
 * a candidate whose origin is the local cluster's designated master is a
 * local-master candidate; origins of other local members are not eligible as
 * local-master defaults. Unmatched origins keep/assume remote-master scope so a
 * backend can attribute remote cluster masters, but local_master is never taken
 * from unverified non-cluster origin. */
static void update_local_candidate(hadc_ctx_t *ctx)
{
    memset(&g_rs.local_cand, 0, sizeof(g_rs.local_cand));
    /* Local-master candidate derived from cluster information (heartbeat/sync):
     * the local cluster master is the effective backup nexthop for slaves, so
     * use the current master's fabric/sync address (reachable on the fabric),
     * not the public DHCP lease gateway. */
    const char *master_id = NULL;
    if (ctx->role == HADC_ROLE_MASTER)
        master_id = ctx->conf.self;
    else if (ctx->conf.designated_master[0])
        master_id = ctx->conf.designated_master;
    else {
        for (size_t i = 0; i < ctx->conf.n_members; i++) {
            if (ctx->peers[i].role_view[0] &&
                !strcmp(ctx->peers[i].role_view, "master") &&
                ctx->peers[i].alive) {
                master_id = ctx->conf.members[i].id;
                break;
            }
            if (ctx->peers[i].master_view[0] &&
                !strcmp(ctx->peers[i].master_view, ctx->conf.members[i].id) &&
                ctx->peers[i].alive) {
                master_id = ctx->conf.members[i].id;
                break;
            }
        }
    }
    if (!master_id || !*master_id)
        return;

    struct in_addr nexthop = {0};
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        if (!strcmp(ctx->conf.members[i].id, master_id)) {
            nexthop = ctx->conf.members[i].sync_address;
            break;
        }
    }
    if (nexthop.s_addr == 0)
        return;
    g_rs.local_cand.gateway = nexthop;
    g_rs.local_cand.scope = HADC_ROUTE_SCOPE_LOCAL_MASTER;
    snprintf(g_rs.local_cand.origin, sizeof(g_rs.local_cand.origin), "%s", master_id);
    g_rs.local_cand.valid = true;
}

static struct in_addr mask_addr(struct in_addr addr, unsigned prefixlen)
{
    struct in_addr out = {0};
    if (prefixlen == 0) {
        out.s_addr = 0;
        return out;
    }
    if (prefixlen >= 32) {
        out = addr;
        return out;
    }
    uint32_t mask = htonl(0xffffffffu << (32 - prefixlen));
    out.s_addr = addr.s_addr & mask;
    return out;
}

static void add_want_prefix(struct in_addr prefix, unsigned prefixlen, const char *ifname)
{
    if (g_rs.n_want_prefixes >= HADC_ROUTING_MAX_PREFIXES)
        return;
    if (!ifname || !*ifname)
        return;
    hadc_routing_prefix_t *p = &g_rs.want_prefixes[g_rs.n_want_prefixes++];
    p->prefix = prefix;
    p->prefixlen = prefixlen;
    snprintf(p->ifname, sizeof(p->ifname), "%s", ifname);
}

static void compute_want_prefixes(hadc_ctx_t *ctx, bool enabled, bool master_owner)
{
    g_rs.n_want_prefixes = 0;
    if (!enabled)
        return;

    /* DHCP/public IP is originated/advertised as a /32 when owned, or always when configured. */
    if (ctx->conf.routing.advertise.public_ip32 != HADC_ADV_PUB_OFF && g_rs.want_advertised_public_ip32 &&
        ctx->lease.address.s_addr != 0) {
        add_want_prefix(ctx->lease.address, 32, ctx->conf.interface);
    }

    /* VIP subnets carry prefix info in config; calculate network prefixes.
     * Only the master owns/advertises these to neighbors. */
    if (ctx->conf.routing.advertise.vip_subnets && master_owner) {
        for (size_t i = 0; i < ctx->conf.cluster.n_ifaces; i++) {
            const hadc_cluster_if_t *ci = &ctx->conf.cluster.ifaces[i];
            for (size_t j = 0; j < ci->n_addrs; j++) {
                struct in_addr net = mask_addr(ci->addrs[j].address, ci->addrs[j].prefixlen);
                add_want_prefix(net, ci->addrs[j].prefixlen, ci->interface);
            }
        }
    }
}


static int rtmsg_send(int type, unsigned flags, struct in_addr prefix, unsigned prefixlen,
                       struct in_addr nexthop)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0)
        return -1;
    struct {
        struct nlmsghdr nh;
        struct rtmsg rt;
        char buf[256];
    } req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nh.nlmsg_type = type;
    req.nh.nlmsg_flags = NLM_F_REQUEST | flags;
    req.nh.nlmsg_seq = 1;
    req.nh.nlmsg_pid = 0;
    req.rt.rtm_family = AF_INET;
    req.rt.rtm_dst_len = (unsigned char)prefixlen;
    req.rt.rtm_table = RT_TABLE_MAIN;
    req.rt.rtm_protocol = RTPROT_OSPF;
    req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
    req.rt.rtm_type = RTN_UNICAST;

    struct rtattr *rta = (struct rtattr *)(((char *)&req) + req.nh.nlmsg_len);
    rta->rta_type = RTA_DST;
    rta->rta_len = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), &prefix.s_addr, 4);
    req.nh.nlmsg_len += RTA_SPACE(4);

    rta = (struct rtattr *)(((char *)&req) + req.nh.nlmsg_len);
    rta->rta_type = RTA_GATEWAY;
    rta->rta_len = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), &nexthop.s_addr, 4);
    req.nh.nlmsg_len += RTA_SPACE(4);

    struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
    int rc = 0;
    if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        rc = -1;
    /* best-effort: drain ack/error for create/replace; ignore for delete */
    if (rc == 0 && (flags & NLM_F_ACK)) {
        char ack[512];
        struct timeval tv = {.tv_sec = 0, .tv_usec = 200000};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ssize_t n = recv(fd, ack, sizeof(ack), 0);
        if (n >= (ssize_t)sizeof(struct nlmsghdr)) {
            struct nlmsghdr *nh = (struct nlmsghdr *)ack;
            if (nh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(nh);
                if (e->error < 0)
                    rc = e->error;
            }
        }
    }
    close(fd);
    return rc;
}

static bool nexthop_reachable_on_fabric(struct in_addr nh, struct ifaddrs *ifas)
{
    if (nh.s_addr == 0 || !ifas) return false;
    for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (!ifa->ifa_netmask) continue;
        struct in_addr a = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        struct in_addr m = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
        if ((a.s_addr & m.s_addr) == (nh.s_addr & m.s_addr))
            return true;
    }
    return false;
}

static void apply_learned_routes(hadc_ctx_t *ctx)
{
    struct ifaddrs *ifas = NULL;

    (void)ctx;
    if (!g_rs.accept_default_route && strcmp(g_rs.backend, "stub") == 0) {
        /* even if not accepting default, still allow non-default prefix install? accept flag
         * controls default route acceptance; learned non-default prefixes are installed as
         * fabric reachability when routing enabled (edge-only). */
    }

    hadc_ospf_learned_route_t learned[HADC_ROUTING_MAX_INSTALLED];
    size_t nlearn = hadc_ospf_learned_routes(ctx, learned, HADC_ROUTING_MAX_INSTALLED);

    if (nlearn > 0 && getifaddrs(&ifas) != 0)
        ifas = NULL;

    hadc_routing_installed_t want[HADC_ROUTING_MAX_INSTALLED];
    size_t nwant = 0;
    for (size_t i = 0; i < nlearn && nwant < HADC_ROUTING_MAX_INSTALLED; i++) {
        if (!learned[i].valid) continue;
        if (learned[i].nexthop.s_addr == 0) continue;
        if (!nexthop_reachable_on_fabric(learned[i].nexthop, ifas)) continue;
        want[nwant].prefix = learned[i].prefix;
        want[nwant].prefixlen = learned[i].prefixlen;
        want[nwant].nexthop = learned[i].nexthop;
        want[nwant].valid = true;
        nwant++;
    }
    if (ifas)
        freeifaddrs(ifas);

    /* remove stale installed routes not desired (or changed nexthop) */
    for (size_t i = 0; i < g_rs.n_installed; ) {
        bool keep = false;
        for (size_t j = 0; j < nwant; j++) {
            if (g_rs.installed[i].prefix.s_addr == want[j].prefix.s_addr &&
                g_rs.installed[i].prefixlen == want[j].prefixlen &&
                g_rs.installed[i].nexthop.s_addr == want[j].nexthop.s_addr) {
                keep = true;
                want[j].valid = false; /* already present */
                break;
            }
        }
        if (keep) { i++; continue; }
        rtmsg_send(RTM_DELROUTE, NLM_F_ACK, g_rs.installed[i].prefix,
                   g_rs.installed[i].prefixlen, g_rs.installed[i].nexthop);
        char p[INET_ADDRSTRLEN], gw[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &g_rs.installed[i].prefix, p, sizeof(p));
        inet_ntop(AF_INET, &g_rs.installed[i].nexthop, gw, sizeof(gw));
        hadc_dbg("routing: removed learned route %s/%u via %s", p, g_rs.installed[i].prefixlen, gw);
        g_rs.installed[i] = g_rs.installed[--g_rs.n_installed];
    }

    for (size_t j = 0; j < nwant; j++) {
        if (!want[j].valid) continue;
        if (g_rs.n_installed >= HADC_ROUTING_MAX_INSTALLED) break;
        /* avoid replacing unrelated/direct routes: try create-only first */
        int rc = rtmsg_send(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
                            want[j].prefix, want[j].prefixlen, want[j].nexthop);
        if (rc == -EEXIST) {
            /* already present (possibly managed externally or by us after restart loss);
             * do not overwrite unknown owner */
            char p[INET_ADDRSTRLEN], gw[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &want[j].prefix, p, sizeof(p));
            inet_ntop(AF_INET, &want[j].nexthop, gw, sizeof(gw));
            hadc_dbg("routing: learned route %s/%u via %s exists, not overwriting", p, want[j].prefixlen, gw);
            continue;
        }
        if (rc < 0) {
            char p[INET_ADDRSTRLEN], gw[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &want[j].prefix, p, sizeof(p));
            inet_ntop(AF_INET, &want[j].nexthop, gw, sizeof(gw));
            hadc_dbg("routing: failed to install learned route %s/%u via %s: %s", p, want[j].prefixlen, gw, strerror(-rc > 0 ? -rc : errno));
            continue;
        }
        g_rs.installed[g_rs.n_installed++] = want[j];
        char p[INET_ADDRSTRLEN], gw[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &want[j].prefix, p, sizeof(p));
        inet_ntop(AF_INET, &want[j].nexthop, gw, sizeof(gw));
        hadc_info("routing: installed learned route %s/%u via %s proto ospf", p, want[j].prefixlen, gw);
    }
}

static void backend_apply_local(hadc_ctx_t *ctx, bool want_pub, bool want_def,
                                  struct in_addr prev_bgw, const char *reason)
{
    /* Local backend (state/planning): track originated prefixes (DHCP/public /32,
     * VIP networks) calculated from local state/config for the native OSPF speaker.
     * No kernel announcement table is installed; local routes/addresses already
     * present are left untouched and never overwritten. Only master-owned
     * prefixes are originated. Effective backup gateway is consumed by executor. */
    g_rs.advertised_public_ip32 = want_pub;
    g_rs.advertised_default_route = want_def;

    /* Install/remove fabric-learned non-default routes from LSDB (edge-only,
     * nexthop must be on local fabric; never self-originated, never default). */
    apply_learned_routes(ctx);

    if (prev_bgw.s_addr != g_rs.backup_gw.s_addr) {
        hadc_desired_t desired;
        hadc_executor_desired(ctx, &ctx->lease, &desired);
        hadc_executor_apply(ctx, &desired, reason ? reason : "routing");
    }
}

static void backend_apply(hadc_ctx_t *ctx, bool want_pub, bool want_def,
                          struct in_addr prev_bgw, const char *reason)
{
    snprintf(g_rs.backend, sizeof(g_rs.backend), "%s",
             ctx->conf.routing.backend[0] ? ctx->conf.routing.backend : "local");
    if (!strcmp(g_rs.backend, "stub")) {
        g_rs.advertised_public_ip32 = want_pub;
        g_rs.advertised_default_route = want_def;
        (void)prev_bgw;
        (void)reason;
        return;
    }
    /* default/local */
    backend_apply_local(ctx, want_pub, want_def, prev_bgw, reason);
}

static void select_backup_gateway(hadc_ctx_t *ctx)
{
    struct in_addr chosen = {0};
    const char *scope = "none";
    const char *origin = "";
    uint64_t now = (uint64_t)hadc_now_ms();
    uint64_t chosen_age = UINT64_MAX; /* effective LSA age of the chosen candidate */

    g_rs.backup_gw.s_addr = 0;
    g_rs.backup_scope[0] = '\0';
    g_rs.backup_origin[0] = '\0';

    if (!g_rs.accept_default_route || g_rs.local_working_default)
        return;

    /* On demote/failover wait until the (new) master has fully promoted and
     * a settle window before installing backup routes, to avoid routing over
     * backup and breaking NAT before promotion completes. */
    if (ctx->role == HADC_ROLE_SLAVE && now < g_rs.backup_hold_until_ms)
        return;
    if (ctx->role == HADC_ROLE_DEMOTING && ctx->handoff_forward_hold)
        return;

    /* Accepted fabric default is backup-path only and never published.
     * Prefer default learned from local cluster member master (local backup);
     * if local cluster master down/unavailable, may use remote cluster master. */
    bool prefer_local = g_rs.local_master_up;

    for (int pass = 0; pass < 2 && chosen.s_addr == 0; pass++) {
        hadc_route_scope_t want = (pass == 0)
            ? (prefer_local ? HADC_ROUTE_SCOPE_LOCAL_MASTER : HADC_ROUTE_SCOPE_REMOTE_MASTER)
            : (prefer_local ? HADC_ROUTE_SCOPE_REMOTE_MASTER : HADC_ROUTE_SCOPE_LOCAL_MASTER);
        if (prefer_local && want == HADC_ROUTE_SCOPE_REMOTE_MASTER)
            break;
        if (want == HADC_ROUTE_SCOPE_LOCAL_MASTER) {
            const hadc_routing_default_candidate_t *c = &g_rs.local_cand;
            if (c->valid && c->gateway.s_addr != 0) {
                /* Treat the local master as fully promoted once it is the
                 * elected/alive master and, when it advertises a default route,
                 * has that advertisement in the fabric LSDB (or after the hold
                 * window elapsed). */
                bool master_ready = g_rs.local_master_up;
                if (master_ready && ctx->conf.routing.advertise.default_route != HADC_ADV_DEF_OFF) {
                    bool seen_default = false;
                    for (size_t i = 0; i < g_rs.n_remote_cands; i++) {
                        const hadc_routing_default_candidate_t *rc = &g_rs.remote_cands[i];
                        if (!rc->valid) continue;
                        if (rc->origin[0] && c->origin[0] && !strcmp(rc->origin, c->origin)) {
                            seen_default = true; /* local master default known in fabric */
                            break;
                        }
                    }
                    /* During hold window require visibility/settle; after hold,
                     * allow selection to avoid starving slaves if LSDB lags. */
                    if (!seen_default && now < g_rs.backup_hold_until_ms)
                        master_ready = false;
                    (void)seen_default;
                }
                if (master_ready) {
                    chosen = c->gateway;
                    scope = scope_name(HADC_ROUTE_SCOPE_LOCAL_MASTER);
                    origin = c->origin;
                }
            }
            continue;
        }
        for (size_t i = 0; i < g_rs.n_remote_cands; i++) {
            const hadc_routing_default_candidate_t *c = &g_rs.remote_cands[i];
            if (!c->valid || c->gateway.s_addr == 0)
                continue;
            /* remote candidates come from backend/fabric; do not accept as local */
            if (c->scope == HADC_ROUTE_SCOPE_LOCAL_MASTER)
                continue;
            /* freshest LSA wins among candidates of the wanted scope */
            if (chosen.s_addr != 0 && chosen_age <= c->age_s)
                continue;
            chosen = c->gateway;
            chosen_age = c->age_s;
            scope = scope_name(HADC_ROUTE_SCOPE_REMOTE_MASTER);
            origin = c->origin;
        }
    }

    if (chosen.s_addr != 0) {
        g_rs.backup_gw = chosen;
        snprintf(g_rs.backup_scope, sizeof(g_rs.backup_scope), "%s", scope);
        snprintf(g_rs.backup_origin, sizeof(g_rs.backup_origin), "%s", origin);
    }
}

int hadc_routing_init(hadc_ctx_t *ctx)
{
    memset(&g_rs, 0, sizeof(g_rs));
    snprintf(g_rs.reason, sizeof(g_rs.reason), "init");
    snprintf(g_rs.backend, sizeof(g_rs.backend), "%s",
             ctx->conf.routing.backend[0] ? ctx->conf.routing.backend : "local");
    snprintf(g_rs.router_id, sizeof(g_rs.router_id), "%s", ctx->conf.ospf.router_id);
    hadc_ospf_init(ctx);
    hadc_routing_reconcile(ctx, "init");
    return 0;
}

void hadc_routing_shutdown(hadc_ctx_t *ctx)
{
    bool standalone = ctx && ctx->conf.n_members == 0;

    if (standalone || hadc_cluster_graceful_active(ctx)) {
        /* Keep installed routes/addresses in place for single-node setups and
         * across graceful restarts; a stop/restart must not delete routes. */
        hadc_ospf_shutdown(ctx);
        snprintf(g_rs.reason, sizeof(g_rs.reason), "shutdown");
        return;
    }

    hadc_routing_reconcile(ctx, "shutdown");
    /* remove routes we installed */
    for (size_t i = 0; i < g_rs.n_installed; i++) {
        rtmsg_send(RTM_DELROUTE, NLM_F_ACK, g_rs.installed[i].prefix,
                   g_rs.installed[i].prefixlen, g_rs.installed[i].nexthop);
    }
    g_rs.n_installed = 0;
    hadc_ospf_shutdown(ctx);
    g_rs.n_want_prefixes = 0;
    g_rs.advertised_public_ip32 = false;
    g_rs.advertised_default_route = false;
    g_rs.public_ip32.s_addr = 0;
    g_rs.backup_gw.s_addr = 0;
    memset(&g_rs.local_cand, 0, sizeof(g_rs.local_cand));
    g_rs.n_remote_cands = 0;
    snprintf(g_rs.reason, sizeof(g_rs.reason), "shutdown");
}

void hadc_routing_set_default_candidates(hadc_ctx_t *ctx,
                                         const hadc_routing_default_candidate_t *cands,
                                         size_t count, const char *reason)
{
    /* Backend-fed fabric candidates. Local-master default is derived from
     * cluster information (heartbeat/sync), not from this feed. */
    hadc_maint_lock();
    size_t n = 0;
    memset(g_rs.remote_cands, 0, sizeof(g_rs.remote_cands));
    for (size_t i = 0; i < count && n < HADC_ROUTING_MAX_CANDIDATES; i++) {
        if (!cands[i].valid || cands[i].gateway.s_addr == 0)
            continue;
        if (cands[i].scope == HADC_ROUTE_SCOPE_LOCAL_MASTER)
            continue; /* enforced from cluster info */
        g_rs.remote_cands[n] = cands[i];
        g_rs.remote_cands[n].scope = HADC_ROUTE_SCOPE_REMOTE_MASTER;
        g_rs.remote_cands[n].origin[HADC_ROUTING_ORIGIN_MAX - 1] = '\0';
        n++;
    }
    g_rs.n_remote_cands = n;
    hadc_maint_unlock();
    hadc_routing_reconcile(ctx, reason ? reason : "candidates");
}

struct in_addr hadc_routing_backup_gateway(hadc_ctx_t *ctx)
{
    struct in_addr none = {0};
    (void)ctx;
    hadc_maint_lock();
    if (!g_rs.accept_default_route) {
        hadc_maint_unlock();
        return none;
    }
    struct in_addr gw = g_rs.backup_gw;
    hadc_maint_unlock();
    return gw;
}

void hadc_routing_reconcile(hadc_ctx_t *ctx, const char *reason)
{
    hadc_maint_lock();
    bool enabled = ctx->conf.routing.enabled;
    bool master_owner = (ctx->role == HADC_ROLE_MASTER || ctx->role == HADC_ROLE_PROMOTING);
    bool healthy_bound = master_owner && ctx->lease.address.s_addr != 0 &&
                         !hadc_gwping_unreachable() &&
                         (ctx->lease.state == HADC_LEASE_BOUND ||
                          ctx->lease.state == HADC_LEASE_RENEW ||
                          ctx->lease.state == HADC_LEASE_REBIND);
    bool backup = on_backup_path(ctx);

    if (reason && *reason)
        snprintf(g_rs.reason, sizeof(g_rs.reason), "%s", reason);
    else
        snprintf(g_rs.reason, sizeof(g_rs.reason), "reconcile");

    /* Delay slave backup routes until the master has fully promoted and a
     * settle window, so failover traffic does not take backup/NAT-breaking paths
     * before the new master is ready. Trigger on demote and on master changes. */
    {
        uint64_t now = (uint64_t)hadc_now_ms();
        const char *dm = ctx->conf.designated_master[0] ? ctx->conf.designated_master : "";
        bool hold = false;
        if (ctx->role == HADC_ROLE_SLAVE || ctx->role == HADC_ROLE_DEMOTING) {
            if (!strcmp(g_rs.reason, "demote"))
                hold = true;
            if (dm[0] && strcmp(dm, g_rs.last_seen_master) != 0)
                hold = true;
        }
        if (ctx->handoff_forward_hold && ctx->handoff_hold_until_ms > now)
            hold = true;
        if (hold) {
            uint64_t hold_ms = ctx->conf.apply.handoff_hold_ms;
            uint64_t until = now + hold_ms;
            if (ctx->handoff_forward_hold && ctx->handoff_hold_until_ms > until)
                until = ctx->handoff_hold_until_ms;
            if (until > g_rs.backup_hold_until_ms)
                g_rs.backup_hold_until_ms = until;
        }
        snprintf(g_rs.last_seen_master, sizeof(g_rs.last_seen_master), "%s", dm);
    }

    g_rs.local_master_up = local_master_alive(ctx);
    g_rs.local_working_default = local_working_default_path(ctx);
    g_rs.using_backup_path = backup;
    g_rs.accept_default_route = enabled && ctx->conf.routing.accept.default_route;
    g_rs.publish_public_ip32 = enabled && ctx->conf.routing.advertise.public_ip32 != HADC_ADV_PUB_OFF;
    g_rs.publish_default_route = enabled && ctx->conf.routing.advertise.default_route != HADC_ADV_DEF_OFF;
    g_rs.public_ip32 = ctx->lease.address;
    snprintf(g_rs.router_id, sizeof(g_rs.router_id), "%s", ctx->conf.ospf.router_id);

    update_local_candidate(ctx);

    /* Refresh fabric-learned default candidates from native OSPF LSDB. */
    g_rs.n_remote_cands = hadc_ospf_default_candidates(ctx, g_rs.remote_cands, HADC_ROUTING_MAX_CANDIDATES);

    /* Desired advertisements: local owned prefixes only, edge-only. Never publish
     * backup routes; withdraw default-route advertisement while on backup.
     * During demotion handoff hold keep public /32 and default route advertised
     * and kernel default route retained until hold completes (VIPs already gone). */
    bool demote_hold = (ctx->role == HADC_ROLE_DEMOTING && ctx->handoff_forward_hold);
    bool hold_bound = demote_hold && ctx->lease.address.s_addr != 0 &&
                      !hadc_gwping_unreachable() &&
                      (ctx->lease.state == HADC_LEASE_BOUND ||
                       ctx->lease.state == HADC_LEASE_RENEW ||
                       ctx->lease.state == HADC_LEASE_REBIND);
    bool want_pub = false;
    if (enabled && ctx->conf.routing.advertise.public_ip32 != HADC_ADV_PUB_OFF && ctx->lease.address.s_addr != 0) {
        if (ctx->conf.routing.advertise.public_ip32 == HADC_ADV_PUB_ALWAYS)
            want_pub = true;
        else
            want_pub = healthy_bound || hold_bound;
    }
    bool want_def = false;
    if (enabled && ctx->conf.routing.advertise.default_route != HADC_ADV_DEF_OFF && ctx->lease.address.s_addr != 0) {
        if (ctx->conf.routing.advertise.default_route == HADC_ADV_DEF_ALWAYS)
            want_def = true;
        else
            want_def = (healthy_bound && !backup) || (hold_bound && !backup);
    }

    if (!enabled) {
        want_pub = false;
        want_def = false;
    }

    g_rs.want_advertised_public_ip32 = want_pub;
    g_rs.want_advertised_default_route = want_def;
    compute_want_prefixes(ctx, enabled, master_owner);

    if (want_pub != g_rs.advertised_public_ip32) {
        hadc_info("routing: %s public /32 %s (router-id %s, %s)", want_pub ? "advertise" : "withdraw",
                  ctx->lease.address.s_addr ? inet_ntoa(ctx->lease.address) : "0.0.0.0",
                  g_rs.router_id[0] ? g_rs.router_id : "unset", g_rs.reason);
    }
    if (want_def != g_rs.advertised_default_route) {
        hadc_info("routing: %s default route 0.0.0.0/0 (router-id %s, %s)",
                  want_def ? "advertise" : "withdraw",
                  g_rs.router_id[0] ? g_rs.router_id : "unset", g_rs.reason);
    }

    struct in_addr prev_bgw = g_rs.backup_gw;
    select_backup_gateway(ctx);

    backend_apply(ctx, want_pub, want_def, prev_bgw, g_rs.reason);
    hadc_ospf_originate(ctx, &g_rs.public_ip32, want_pub, want_def, NULL, 0);
    /* tick (hello/FSM/LSDB/SPF) runs on the OSPF thread, not the main loop */
    g_rs.n_remote_cands = hadc_ospf_default_candidates(ctx, g_rs.remote_cands, HADC_ROUTING_MAX_CANDIDATES);
    if (prev_bgw.s_addr != g_rs.backup_gw.s_addr) {
        char oldgw[INET_ADDRSTRLEN] = "0.0.0.0", cur[INET_ADDRSTRLEN] = "0.0.0.0";
        if (prev_bgw.s_addr)
            inet_ntop(AF_INET, &prev_bgw, oldgw, sizeof(oldgw));
        if (g_rs.backup_gw.s_addr)
            inet_ntop(AF_INET, &g_rs.backup_gw, cur, sizeof(cur));
        hadc_info("routing: backup gateway %s -> %s (%s, %s, %s)", oldgw, cur,
                  g_rs.backup_scope[0] ? g_rs.backup_scope : "none", g_rs.reason,
                  g_rs.local_master_up ? "local-master-up" : "local-master-down");
    }
    hadc_maint_unlock();
}



const char *hadc_routing_router_id(hadc_ctx_t *ctx)
{
    if (ctx && ctx->conf.ospf.router_id[0])
        return ctx->conf.ospf.router_id;
    hadc_maint_lock();
    const char *rid = g_rs.router_id;
    hadc_maint_unlock();
    return rid;
}

json_t *hadc_routing_status(hadc_ctx_t *ctx)
{
    hadc_maint_lock();
    char pub[INET_ADDRSTRLEN] = "0.0.0.0";
    char bgw[INET_ADDRSTRLEN] = "0.0.0.0";
    if (g_rs.public_ip32.s_addr)
        inet_ntop(AF_INET, &g_rs.public_ip32, pub, sizeof(pub));
    if (g_rs.backup_gw.s_addr)
        inet_ntop(AF_INET, &g_rs.backup_gw, bgw, sizeof(bgw));

    json_t *cands = json_array();
    if (g_rs.local_cand.valid && g_rs.local_cand.gateway.s_addr != 0) {
        char gw[INET_ADDRSTRLEN] = "0.0.0.0";
        inet_ntop(AF_INET, &g_rs.local_cand.gateway, gw, sizeof(gw));
        json_array_append_new(cands, json_pack("{s:s,s:s,s:s,s:b}", "gateway", gw, "scope",
                                               "local_master", "origin",
                                               g_rs.local_cand.origin, "valid", true));
    }
    for (size_t i = 0; i < g_rs.n_remote_cands; i++) {
        char gw[INET_ADDRSTRLEN] = "0.0.0.0";
        if (g_rs.remote_cands[i].gateway.s_addr)
            inet_ntop(AF_INET, &g_rs.remote_cands[i].gateway, gw, sizeof(gw));
        json_array_append_new(cands, json_pack("{s:s,s:s,s:s,s:b}", "gateway", gw, "scope",
                                               "remote_master", "origin",
                                               g_rs.remote_cands[i].origin, "valid",
                                               g_rs.remote_cands[i].valid));
    }
    /* remaining g_rs fields are read below while holding maint_lock */

    int cand_count = g_rs.n_remote_cands + ((g_rs.local_cand.valid && g_rs.local_cand.gateway.s_addr) ? 1 : 0);
    json_t *prefixes = json_array();
    for (size_t i = 0; i < g_rs.n_want_prefixes; i++) {
        char dst[INET_ADDRSTRLEN] = "0.0.0.0";
        inet_ntop(AF_INET, &g_rs.want_prefixes[i].prefix, dst, sizeof(dst));
        json_array_append_new(prefixes, json_pack("{s:s,s:i,s:s}", "prefix", dst, "prefixlen",
                                                  (int)g_rs.want_prefixes[i].prefixlen, "interface",
                                                  g_rs.want_prefixes[i].ifname));
    }

    json_t *o = json_object();
    if (!o) {
        json_decref(cands);
        json_decref(prefixes);
        return json_object();
    }
    json_object_set_new(o, "enabled", json_boolean(ctx->conf.routing.enabled));
    {
        const char *pub_mode = "off", *def_mode = "off";
        switch (ctx->conf.routing.advertise.public_ip32) {
        case HADC_ADV_PUB_ALWAYS: pub_mode = "always"; break;
        case HADC_ADV_PUB_MASTER: pub_mode = "on"; break;
        default: pub_mode = "off"; break;
        }
        switch (ctx->conf.routing.advertise.default_route) {
        case HADC_ADV_DEF_ALWAYS: def_mode = "always"; break;
        case HADC_ADV_DEF_MASTER: def_mode = "on"; break;
        default: def_mode = "off"; break;
        }
        json_object_set_new(o, "advertise", json_pack("{s:s,s:b,s:s}",
            "public_ip32", pub_mode,
            "vip_subnets", ctx->conf.routing.advertise.vip_subnets,
            "default_route", def_mode));
    }
    json_object_set_new(o, "accept", json_pack("{s:b}",
        "default_route", ctx->conf.routing.accept.default_route));
    json_t *state = json_object();
    if (state) {
        json_object_set_new(state, "advertised_public_ip32", json_boolean(g_rs.advertised_public_ip32));
        json_object_set_new(state, "advertised_default_route", json_boolean(g_rs.advertised_default_route));
        json_object_set_new(state, "using_backup_path", json_boolean(g_rs.using_backup_path));
        json_object_set_new(state, "local_master_up", json_boolean(g_rs.local_master_up));
        json_object_set_new(state, "local_working_default", json_boolean(g_rs.local_working_default));
        json_object_set_new(state, "public_ip32", json_string(pub));
        json_object_set_new(state, "backup_gateway", json_string(bgw));
        json_object_set_new(state, "backup_scope", json_string(g_rs.backup_scope[0] ? g_rs.backup_scope : "none"));
        json_object_set_new(state, "backup_origin", json_string(g_rs.backup_origin));
        json_object_set_new(state, "reason", json_string(g_rs.reason));
        json_object_set_new(state, "candidate_count", json_integer(cand_count));
        json_object_set_new(state, "candidates", cands ? cands : json_array());
        json_object_set_new(state, "originated_prefix_count", json_integer((int)g_rs.n_want_prefixes));
        json_object_set_new(state, "originated_prefixes", prefixes ? prefixes : json_array());
        json_object_set_new(state, "installed_route_count", json_integer((int)g_rs.n_installed));
        json_object_set_new(o, "state", state);
    } else {
        json_decref(cands);
        json_decref(prefixes);
    }
    json_object_set_new(o, "backend", json_pack("{s:s,s:s}", "name", g_rs.backend, "router_id", g_rs.router_id));

    json_t *ost = hadc_ospf_status(ctx);
    if (!ost) ost = json_object();
    json_object_set_new(ost, "router_id", json_string(ctx->conf.ospf.router_id));
    json_t *ifaces = json_array();
    for (size_t i = 0; i < ctx->conf.ospf.n_interfaces; i++)
        json_array_append_new(ifaces, json_string(ctx->conf.ospf.interfaces[i]));
    json_object_set_new(ost, "interfaces", ifaces);
    json_object_set_new(ost, "auth", json_pack("{s:s}", "type",
        ctx->conf.ospf.auth.type == 2 ? "md5" :
        (ctx->conf.ospf.auth.type == 1 ? "plaintext" : "none")));
    json_object_set_new(o, "ospf", ost);
    hadc_maint_unlock();
    return o;
}
