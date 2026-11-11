/* Inter-cluster routing (edge-only, local-prefix origination). Modular core:
 * compute desired advertisement/accept state from ha-dhcpc role+lease+health,
 * select fabric-learned backup defaults from attributed candidates, apply through
 * a backend interface (stub/no-op here), and expose status. Backup routes and
 * fabric-learned defaults are never published. */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <string.h>

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/log.h"
#include "ha-dhcpc/routing.h"
#include "internal.h"

#define HADC_ROUTING_MAX_PREFIXES 64

typedef struct {
    struct in_addr prefix;
    unsigned prefixlen;
    char ifname[HADC_IFNAME_MAX];
} hadc_routing_prefix_t;

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
    hadc_routing_default_candidate_t local_cand; /* from cluster/heartbeat info */
    hadc_routing_default_candidate_t remote_cands[HADC_ROUTING_MAX_CANDIDATES];
    size_t n_remote_cands;
    hadc_routing_prefix_t want_prefixes[HADC_ROUTING_MAX_PREFIXES];
    size_t n_want_prefixes;

} hadc_routing_state_t;

static hadc_routing_state_t g_rs;

static bool local_master_alive(hadc_ctx_t *ctx)
{
    if (ctx->role == HADC_ROLE_MASTER)
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
    if (ctx->role == HADC_ROLE_MASTER) {
        return ctx->lease.address.s_addr != 0 && ctx->lease.gateway.s_addr != 0 &&
               !hadc_gwping_unreachable() && ctx->lease.state == HADC_LEASE_BOUND;
    }
    /* Slaves have no primary DHCP default route of their own. */
    return false;
}

static bool on_backup_path(hadc_ctx_t *ctx)
{
    if (ctx->role == HADC_ROLE_MASTER)
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
     * designated master is the local cluster master by config/cluster state; its
     * default gateway is known from the synced lease when available. */
    if (!ctx->conf.designated_master[0])
        return;
    if (ctx->lease.gateway.s_addr == 0)
        return;
    /* Only meaningful when we have cluster-master context for this lease/gateway. */
    g_rs.local_cand.gateway = ctx->lease.gateway;
    g_rs.local_cand.scope = HADC_ROUTE_SCOPE_LOCAL_MASTER;
    snprintf(g_rs.local_cand.origin, sizeof(g_rs.local_cand.origin), "%s",
             ctx->conf.designated_master);
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

    /* DHCP/public IP is always originated/advertised as a /32 when owned. */
    if (ctx->conf.routing.advertise.public_ip32 && g_rs.want_advertised_public_ip32 &&
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
    (void)reason;
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

    g_rs.backup_gw.s_addr = 0;
    g_rs.backup_scope[0] = '\0';
    g_rs.backup_origin[0] = '\0';

    if (!g_rs.accept_default_route || g_rs.local_working_default)
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
            if (c->valid && c->gateway.s_addr != 0 &&
                !strcmp(c->origin, ctx->conf.designated_master)) {
                chosen = c->gateway;
                scope = scope_name(HADC_ROUTE_SCOPE_LOCAL_MASTER);
                origin = c->origin;
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
            chosen = c->gateway;
            scope = scope_name(HADC_ROUTE_SCOPE_REMOTE_MASTER);
            origin = c->origin;
            break;
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
    hadc_routing_reconcile(ctx, "init");
    return 0;
}

void hadc_routing_shutdown(hadc_ctx_t *ctx)
{
    hadc_routing_reconcile(ctx, "shutdown");
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
    hadc_routing_reconcile(ctx, reason ? reason : "candidates");
}

struct in_addr hadc_routing_backup_gateway(hadc_ctx_t *ctx)
{
    struct in_addr none = {0};
    (void)ctx;
    if (!g_rs.accept_default_route)
        return none;
    return g_rs.backup_gw;
}

void hadc_routing_reconcile(hadc_ctx_t *ctx, const char *reason)
{
    bool enabled = ctx->conf.routing.enabled;
    bool master_owner = (ctx->role == HADC_ROLE_MASTER);
    bool healthy_bound = master_owner && ctx->lease.state == HADC_LEASE_BOUND &&
                         ctx->lease.address.s_addr != 0 && !hadc_gwping_unreachable();
    bool backup = on_backup_path(ctx);

    if (reason && *reason)
        snprintf(g_rs.reason, sizeof(g_rs.reason), "%s", reason);
    else
        snprintf(g_rs.reason, sizeof(g_rs.reason), "reconcile");

    g_rs.local_master_up = local_master_alive(ctx);
    g_rs.local_working_default = local_working_default_path(ctx);
    g_rs.using_backup_path = backup;
    g_rs.accept_default_route = enabled && ctx->conf.routing.accept.default_route;
    g_rs.publish_public_ip32 = enabled && ctx->conf.routing.advertise.public_ip32;
    g_rs.publish_default_route = enabled && ctx->conf.routing.advertise.default_route;
    g_rs.public_ip32 = ctx->lease.address;
    snprintf(g_rs.router_id, sizeof(g_rs.router_id), "%s", ctx->conf.ospf.router_id);

    update_local_candidate(ctx);

    /* Desired advertisements: local owned prefixes only, edge-only. Never publish
     * backup routes; withdraw default-route advertisement while on backup. */
    bool want_pub = enabled && g_rs.publish_public_ip32 && healthy_bound;
    bool want_def = enabled && g_rs.publish_default_route && healthy_bound && !backup;

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
}



const char *hadc_routing_router_id(hadc_ctx_t *ctx)
{
    if (ctx && ctx->conf.ospf.router_id[0])
        return ctx->conf.ospf.router_id;
    return g_rs.router_id;
}

json_t *hadc_routing_status(hadc_ctx_t *ctx)
{
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

    int cand_count = g_rs.n_remote_cands + ((g_rs.local_cand.valid && g_rs.local_cand.gateway.s_addr) ? 1 : 0);
    json_t *prefixes = json_array();
    for (size_t i = 0; i < g_rs.n_want_prefixes; i++) {
        char dst[INET_ADDRSTRLEN] = "0.0.0.0";
        inet_ntop(AF_INET, &g_rs.want_prefixes[i].prefix, dst, sizeof(dst));
        json_array_append_new(prefixes, json_pack("{s:s,s:i,s:s}", "prefix", dst, "prefixlen",
                                                  (int)g_rs.want_prefixes[i].prefixlen, "interface",
                                                  g_rs.want_prefixes[i].ifname));
    }

    json_t *o = json_pack(
        "{s:b, s:{s:b,s:b,s:b}, s:{s:b}, s:{s:b,s:b,s:b,s:b,s:b,s:s,s:s,s:s,s:s,s:s,s:i,s:o,s:i,s:o}, s:{s:s,s:s}, s:o}",
        "enabled", ctx->conf.routing.enabled,
        "advertise",
            "public_ip32", ctx->conf.routing.advertise.public_ip32,
            "vip_subnets", ctx->conf.routing.advertise.vip_subnets,
            "default_route", ctx->conf.routing.advertise.default_route,
        "accept",
            "default_route", ctx->conf.routing.accept.default_route,
        "state",
            "advertised_public_ip32", g_rs.advertised_public_ip32,
            "advertised_default_route", g_rs.advertised_default_route,
            "using_backup_path", g_rs.using_backup_path,
            "local_master_up", g_rs.local_master_up,
            "local_working_default", g_rs.local_working_default,
            "public_ip32", pub,
            "backup_gateway", bgw,
            "backup_scope", g_rs.backup_scope[0] ? g_rs.backup_scope : "none",
            "backup_origin", g_rs.backup_origin,
            "reason", g_rs.reason,
            "candidate_count", cand_count,
            "candidates", cands ? cands : json_array(),
            "originated_prefix_count", (int)g_rs.n_want_prefixes,
            "originated_prefixes", prefixes ? prefixes : json_array(),
        "backend",
            "name", g_rs.backend,
            "router_id", g_rs.router_id,
        "ospf", json_pack("{s:s, s:o, s:{s:s}}",
            "router_id", ctx->conf.ospf.router_id,
            "interfaces", (json_t *)({
                json_t *a = json_array();
                for (size_t i = 0; i < ctx->conf.ospf.n_interfaces; i++)
                    json_array_append_new(a, json_string(ctx->conf.ospf.interfaces[i]));
                a;
            }),
            "auth",
                "type",
                ctx->conf.ospf.auth.type == 2 ? "md5" :
                (ctx->conf.ospf.auth.type == 1 ? "plaintext" : "none")
        ));
    if (!o)
        return json_object();
    return o;
}
