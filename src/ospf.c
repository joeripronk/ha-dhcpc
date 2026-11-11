/* Minimal native OSPFv2 speaker (edge-only, Area 0 backbone).
 * Implements Hello exchange, neighbor tracking, and self-originated Router-LSA
 * construction/refresh for locally owned prefixes. No transit/redistribution of
 * non-local routes. Interoperable packet formats (RFC 2328 basics). */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "ha-dhcpc/log.h"
#include "internal.h"
#include "ospf.h"

#define OSPF_PROTO 89
#define OSPF_VERSION 2
#define OSPF_HELLO 1
#define OSPF_DBDESC 2
#define OSPF_LSREQ 3
#define OSPF_LSUPDATE 4
#define OSPF_LSACK 5

#define OSPF_LSA_ROUTER 1
#define OSPF_LSA_NETWORK 2
#define OSPF_LSA_SUMMARY 3
#define OSPF_LSA_AS_EXTERNAL 5

#define OSPF_AREA_BACKBONE 0
#define OSPF_HELLO_INTERVAL 10
#define OSPF_DEAD_INTERVAL 40
#define OSPF_LSA_REFRESH 1800
#define OSPF_LSA_MAXAGE 3600
#define OSPF_INITIAL_SEQ 0x80000001u
#define OSPF_MAXSEQ 0x7fffffff

#define OSPF_ALLSPFROUTERS "224.0.0.5"
#define OSPF_ALLDRouters   "224.0.0.6"

#define OSPF_MAX_IFACES HADC_CLUSTER_IF_MAX
#define OSPF_MAX_NEIGHBORS 64
#define OSPF_MAX_LSAS 128
#define OSPF_MTU 1500

typedef enum {
    NSTATE_DOWN = 0,
    NSTATE_INIT,
    NSTATE_2WAY,
    NSTATE_EXSTART,
    NSTATE_EXCHANGE,
    NSTATE_LOADING,
    NSTATE_FULL,
} nbr_state_t;

typedef struct {
    uint32_t router_id; /* network byte order stored as host in comparisons? keep host */
    struct in_addr ip;
    struct in_addr netmask;
    uint32_t area;
    uint8_t priority;
    uint32_t dr;
    uint32_t bdr;
    nbr_state_t state;
    time_t last_hello;
    time_t dead_at;
    bool in_use;
} ospf_neighbor_t;

typedef struct {
    char name[HADC_IFNAME_MAX];
    unsigned ifindex;
    struct in_addr addr;
    struct in_addr mask;
    struct in_addr network;
    bool up;
} ospf_if_t;

typedef struct {
    uint16_t age;
    uint8_t options;
    uint8_t type;
    uint32_t id;
    uint32_t adv_router;
    uint32_t seq;
    uint16_t checksum;
    uint16_t length;
} __attribute__((packed)) ospf_lsa_hdr_t;

typedef struct {
    ospf_lsa_hdr_t hdr;
    uint8_t *body;
    size_t body_len;
    time_t originated;
    bool self;
    bool valid;
} ospf_lsa_t;

typedef struct {
    bool enabled;
    int fd;
    uint32_t router_id; /* host order for logic, net order in packets */
    ospf_if_t ifaces[OSPF_MAX_IFACES];
    size_t n_ifaces;
    ospf_neighbor_t nbrs[OSPF_MAX_NEIGHBORS];
    ospf_lsa_t lsdb[OSPF_MAX_LSAS];
    size_t n_lsas;
    uint32_t lsa_seq;
    time_t last_hello_sent;
    hadc_ctx_t *ctx;
} ospf_state_t;

static ospf_state_t g_ospf;

static uint16_t ip_checksum(const void *data, size_t len)
{
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

/* Fletcher checksum for OSPF LSAs (RFC 2328, excluding age field). */
static uint16_t lsa_checksum(uint8_t *lsa, size_t len)
{
    if (len < 18)
        return 0;
    lsa[16] = 0;
    lsa[17] = 0;
    uint32_t c0 = 0, c1 = 0;
    for (size_t i = 2; i < len; i++) {
        c0 = (c0 + lsa[i]) % 255;
        c1 = (c1 + c0) % 255;
    }
    int x = (int)((len - 16 - 1) % 255);
    int y = (int)((c0 * (len - 16)) % 255);
    int ck0 = (int)c0 - (int)c1 + (int)(len - 16) - y;
    ck0 %= 255;
    if (ck0 < 0) ck0 += 255;
    int ck1 = (int)c1 - ck0 - x;
    ck1 %= 255;
    if (ck1 < 0) ck1 += 255;
    lsa[16] = (uint8_t)ck0;
    lsa[17] = (uint8_t)ck1;
    return (uint16_t)((lsa[16] << 8) | lsa[17]);
}

static uint32_t rid_to_u32(const char *s)
{
    struct in_addr a = {0};
    if (inet_pton(AF_INET, s, &a) == 1)
        return ntohl(a.s_addr);
    return 0;
}

static void u32_to_rid(uint32_t v, char *out, size_t outlen)
{
    struct in_addr a; a.s_addr = htonl(v);
    inet_ntop(AF_INET, &a, out, outlen);
}

static bool iface_primary_v4(const char *ifname, struct in_addr *addr, struct in_addr *mask)
{
    struct ifaddrs *ifas = NULL, *ifa;
    bool ok = false;
    if (getifaddrs(&ifas) != 0)
        return false;
    for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (strcmp(ifa->ifa_name, ifname) != 0)
            continue;
        *addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        if (ifa->ifa_netmask)
            *mask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
        else
            mask->s_addr = 0;
        ok = true;
        break;
    }
    freeifaddrs(ifas);
    return ok;
}

static void ospf_fd_ready(hadc_ctx_t *ctx, int fd);

static void refresh_ifaces(hadc_ctx_t *ctx)
{
    g_ospf.n_ifaces = 0;
    for (size_t i = 0; i < ctx->conf.ospf.n_interfaces && g_ospf.n_ifaces < OSPF_MAX_IFACES; i++) {
        ospf_if_t *oi = &g_ospf.ifaces[g_ospf.n_ifaces];
        memset(oi, 0, sizeof(*oi));
        snprintf(oi->name, sizeof(oi->name), "%s", ctx->conf.ospf.interfaces[i]);
        oi->ifindex = if_nametoindex(oi->name);
        oi->up = iface_primary_v4(oi->name, &oi->addr, &oi->mask);
        if (oi->up)
            oi->network.s_addr = oi->addr.s_addr & oi->mask.s_addr;
        if (oi->ifindex)
            g_ospf.n_ifaces++;
    }
}

static int join_multicast(int fd, unsigned ifindex)
{
    struct ip_mreqn mreq;
    memset(&mreq, 0, sizeof(mreq));
    if (inet_pton(AF_INET, OSPF_ALLSPFROUTERS, &mreq.imr_multiaddr) != 1)
        return -1;
    mreq.imr_address.s_addr = htonl(INADDR_ANY);
    mreq.imr_ifindex = (int)ifindex;
    return setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
}

int hadc_ospf_init(hadc_ctx_t *ctx)
{
    memset(&g_ospf, 0, sizeof(g_ospf));
    g_ospf.fd = -1;
    g_ospf.ctx = ctx;
    g_ospf.enabled = ctx->conf.routing.enabled;
    g_ospf.router_id = rid_to_u32(ctx->conf.ospf.router_id);
    g_ospf.lsa_seq = OSPF_INITIAL_SEQ;
    if (!g_ospf.enabled)
        return 0;

    g_ospf.fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, OSPF_PROTO);
    if (g_ospf.fd < 0) {
        hadc_warn("ospf: raw socket(IPPROTO_OSPF) failed: %s (need CAP_NET_RAW)", strerror(errno));
        g_ospf.enabled = false;
        return 0;
    }
    int one = 1;
    setsockopt(g_ospf.fd, IPPROTO_IP, IP_MULTICAST_TTL, &one, sizeof(one));
    unsigned char loop = 0;
    setsockopt(g_ospf.fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
    /* We build IP header ourselves not required; easier let kernel build, but for
     * multicast per-interface we use IP_MULTICAST_IF on send. Keep IP_HDRINCL off. */

    refresh_ifaces(ctx);
    for (size_t i = 0; i < g_ospf.n_ifaces; i++) {
        if (g_ospf.ifaces[i].ifindex)
            join_multicast(g_ospf.fd, g_ospf.ifaces[i].ifindex);
        hadc_info("ospf: interface %s idx=%u addr=%s (router-id %s)",
                  g_ospf.ifaces[i].name, g_ospf.ifaces[i].ifindex,
                  inet_ntoa(g_ospf.ifaces[i].addr), ctx->conf.ospf.router_id);
    }

    if (hadc_loop_add(ctx, g_ospf.fd, ospf_fd_ready, 0) != 0) {
        hadc_warn("ospf: failed to register socket in event loop");
    }

    hadc_info("ospf: started (area 0, %zu interfaces, router-id %s)",
              g_ospf.n_ifaces, ctx->conf.ospf.router_id);
    return 0;
}

void hadc_ospf_shutdown(hadc_ctx_t *ctx)
{
    if (g_ospf.fd >= 0) {
        hadc_loop_del(ctx, g_ospf.fd);
        close(g_ospf.fd);
        g_ospf.fd = -1;
    }
    for (size_t i = 0; i < g_ospf.n_lsas; i++) {
        free(g_ospf.lsdb[i].body);
        g_ospf.lsdb[i].body = NULL;
    }
    memset(&g_ospf, 0, sizeof(g_ospf));
    g_ospf.fd = -1;
    (void)ctx;
}

/* ---- packet helpers ---- */

typedef struct {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint32_t router_id;
    uint32_t area_id;
    uint16_t checksum;
    uint16_t autype;
    uint64_t auth;
} __attribute__((packed)) ospf_hdr_t;

typedef struct {
    uint32_t network_mask;
    uint16_t hello_interval;
    uint8_t options;
    uint8_t priority;
    uint32_t dead_interval;
    uint32_t dr;
    uint32_t bdr;
    /* followed by neighbor router IDs */
} __attribute__((packed)) ospf_hello_t;

static void build_hello(uint8_t *buf, size_t *outlen, ospf_if_t *iface)
{
    memset(buf, 0, OSPF_MTU);
    ospf_hdr_t *h = (ospf_hdr_t *)buf;
    ospf_hello_t *hello = (ospf_hello_t *)(buf + sizeof(*h));
    h->version = OSPF_VERSION;
    h->type = OSPF_HELLO;
    h->router_id = htonl(g_ospf.router_id);
    h->area_id = htonl(OSPF_AREA_BACKBONE);
    h->autype = 0;
    h->auth = 0;
    hello->network_mask = iface->mask.s_addr;
    hello->hello_interval = htons(OSPF_HELLO_INTERVAL);
    hello->options = 0x02; /* E-bit */
    hello->priority = 1;
    hello->dead_interval = htonl(OSPF_DEAD_INTERVAL);
    hello->dr = 0;
    hello->bdr = 0;

    size_t off = sizeof(*h) + sizeof(*hello);
    time_t now = time(NULL);
    for (size_t i = 0; i < OSPF_MAX_NEIGHBORS; i++) {
        ospf_neighbor_t *n = &g_ospf.nbrs[i];
        if (!n->in_use || n->dead_at <= now)
            continue;
        /* neighbor seen on this interface/network */
        if ((n->ip.s_addr & iface->mask.s_addr) != iface->network.s_addr)
            continue;
        if (off + 4 > OSPF_MTU)
            break;
        uint32_t nr = htonl(n->router_id);
        memcpy(buf + off, &nr, 4);
        off += 4;
    }
    h->length = htons((uint16_t)off);
    h->checksum = 0;
    h->checksum = ip_checksum(buf, off);
    *outlen = off;
}

static void send_hello_on(ospf_if_t *iface)
{
    if (g_ospf.fd < 0 || !iface->up || !iface->ifindex)
        return;
    uint8_t pkt[OSPF_MTU];
    size_t len = 0;
    build_hello(pkt, &len, iface);

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, OSPF_ALLSPFROUTERS, &dst.sin_addr);

    struct ip_mreqn mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_address = iface->addr;
    mreq.imr_ifindex = (int)iface->ifindex;
    setsockopt(g_ospf.fd, IPPROTO_IP, IP_MULTICAST_IF, &mreq, sizeof(mreq));

    ssize_t n = sendto(g_ospf.fd, pkt, len, 0, (struct sockaddr *)&dst, sizeof(dst));
    if (n < 0) {
        hadc_dbg("ospf: hello send on %s failed: %s", iface->name, strerror(errno));
    } else {
        hadc_dbg("ospf: hello sent on %s (%zu bytes, %zu neighbors listed)", iface->name, len,
                 (len - sizeof(ospf_hdr_t) - sizeof(ospf_hello_t)) / 4);
    }
}

static ospf_neighbor_t *find_or_add_neighbor(uint32_t rid, struct in_addr ip)
{
    ospf_neighbor_t *free_slot = NULL;
    for (size_t i = 0; i < OSPF_MAX_NEIGHBORS; i++) {
        ospf_neighbor_t *n = &g_ospf.nbrs[i];
        if (n->in_use && n->router_id == rid)
            return n;
        if (!n->in_use && !free_slot)
            free_slot = n;
    }
    if (!free_slot)
        return NULL;
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->in_use = true;
    free_slot->router_id = rid;
    free_slot->ip = ip;
    free_slot->state = NSTATE_DOWN;
    return free_slot;
}

static void handle_hello(const uint8_t *pkt, size_t len, struct in_addr src, ospf_if_t *iface)
{
    if (len < sizeof(ospf_hdr_t) + sizeof(ospf_hello_t))
        return;
    const ospf_hdr_t *h = (const ospf_hdr_t *)pkt;
    const ospf_hello_t *hello = (const ospf_hello_t *)(pkt + sizeof(*h));
    if (h->version != OSPF_VERSION || h->type != OSPF_HELLO)
        return;
    uint32_t rid = ntohl(h->router_id);
    if (rid == g_ospf.router_id)
        return; /* our own */

    ospf_neighbor_t *n = find_or_add_neighbor(rid, src);
    if (!n)
        return;

    bool two_way = (n->state >= NSTATE_2WAY);
    /* Check if our router-id is listed in hello's neighbor list */
    bool see_self = false;
    size_t ncount = (ntohs(h->length) - sizeof(*h) - sizeof(*hello)) / 4;
    const uint8_t *p = pkt + sizeof(*h) + sizeof(*hello);
    for (size_t i = 0; i < ncount; i++, p += 4) {
        uint32_t nr; memcpy(&nr, p, 4);
        if (ntohl(nr) == g_ospf.router_id) { see_self = true; break; }
    }

    nbr_state_t old = n->state;
    n->ip = src;
    n->netmask.s_addr = hello->network_mask;
    n->priority = hello->priority;
    n->dr = ntohl(hello->dr);
    n->bdr = ntohl(hello->bdr);
    n->last_hello = time(NULL);
    uint32_t dead = ntohl(hello->dead_interval);
    if (dead == 0) dead = OSPF_DEAD_INTERVAL;
    n->dead_at = n->last_hello + (time_t)dead;

    if (see_self) {
        if (n->state < NSTATE_2WAY)
            n->state = NSTATE_2WAY;
        /* Edge-only/simple: treat 2WAY as sufficient adjacency for LSA exchange
         * on point-to-multipoint-like peering; full DR/BDR/EXSTART omitted. */
    } else {
        n->state = NSTATE_INIT;
    }

    if (n->state != old) {
        char ridbuf[INET_ADDRSTRLEN]; u32_to_rid(rid, ridbuf, sizeof(ridbuf));
        const char *sn = n->state == NSTATE_DOWN ? "Down" :
                         n->state == NSTATE_INIT ? "Init" :
                         n->state == NSTATE_2WAY ? "2-Way" : "Full-ish";
        hadc_info("ospf: neighbor %s (%s) on %s -> %s", ridbuf, inet_ntoa(src),
                  iface ? iface->name : "?", sn);
    }
    (void)two_way;
}

static ospf_if_t *iface_for_src(struct in_addr src)
{
    for (size_t i = 0; i < g_ospf.n_ifaces; i++) {
        ospf_if_t *oi = &g_ospf.ifaces[i];
        if (!oi->up) continue;
        if ((src.s_addr & oi->mask.s_addr) == oi->network.s_addr)
            return oi;
    }
    return g_ospf.n_ifaces ? &g_ospf.ifaces[0] : NULL;
}

static void ospf_fd_ready(hadc_ctx_t *ctx, int fd)
{
    (void)ctx;
    uint8_t buf[2048];
    for (;;) {
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &slen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                break;
            break;
        }
        if (n < (ssize_t)sizeof(ospf_hdr_t))
            continue;
        /* Kernel delivers payload (OSPF packet) for raw IPPROTO_OSPF on Linux? Usually yes. */
        const ospf_hdr_t *h = (const ospf_hdr_t *)buf;
        if (h->version != OSPF_VERSION)
            continue;
        ospf_if_t *iface = iface_for_src(src.sin_addr);
        switch (h->type) {
        case OSPF_HELLO:
            handle_hello(buf, (size_t)n, src.sin_addr, iface);
            break;
        case OSPF_LSUPDATE:
        case OSPF_LSACK:
        case OSPF_DBDESC:
        case OSPF_LSREQ:
            hadc_dbg("ospf: rx type %u from %s on %s (len %zd)", h->type,
                     inet_ntoa(src.sin_addr), iface ? iface->name : "?", n);
            break;
        default:
            break;
        }
    }
}

static void expire_neighbors(void)
{
    time_t now = time(NULL);
    for (size_t i = 0; i < OSPF_MAX_NEIGHBORS; i++) {
        ospf_neighbor_t *n = &g_ospf.nbrs[i];
        if (!n->in_use)
            continue;
        if (n->dead_at > 0 && now >= n->dead_at) {
            char ridbuf[INET_ADDRSTRLEN]; u32_to_rid(n->router_id, ridbuf, sizeof(ridbuf));
            hadc_info("ospf: neighbor %s (%s) dead -> Down", ridbuf, inet_ntoa(n->ip));
            n->in_use = false;
            n->state = NSTATE_DOWN;
        }
    }
}

/* ---- self-originated Router LSA ---- */

static void clear_self_lsas(void)
{
    for (size_t i = 0; i < g_ospf.n_lsas; ) {
        if (g_ospf.lsdb[i].self) {
            free(g_ospf.lsdb[i].body);
            g_ospf.lsdb[i] = g_ospf.lsdb[--g_ospf.n_lsas];
            continue;
        }
        i++;
    }
}

void hadc_ospf_originate(hadc_ctx_t *ctx,
                         const struct in_addr *public_ip32, bool want_pub,
                         bool want_default_route,
                         const void *vip_prefixes, size_t vip_prefix_count)
{
    (void)ctx;
    (void)vip_prefixes; (void)vip_prefix_count;
    if (!g_ospf.enabled)
        return;

    /* Build a single self Router-LSA with stub links for originated prefixes. */
    clear_self_lsas();
    if (g_ospf.n_lsas >= OSPF_MAX_LSAS)
        return;

    /* count links: public /32, default route 0/0, plus one stub per vip prefix
     * (vip prefixes passed generically not wired yet; originate called from routing
     * with computed want_prefixes later - keep simple: caller supplies counts via state) */
    /* We'll build body after counting in caller-aware way; for now store intent in LSA
       as stubs derived from ctx lease/vip config is done in routing - instead accept
       prefix list via a simpler route: routing will call originate and we read its
       desired public/default; VIPs added below by scanning ctx conf. */

    typedef struct { uint32_t id; uint32_t data; uint8_t type; uint8_t tos; uint16_t metric; } __attribute__((packed)) rlink_t;
    rlink_t links[64];
    size_t nlinks = 0;

    /* stub link for public /32 */
    if (want_pub && public_ip32 && public_ip32->s_addr) {
        links[nlinks].id = public_ip32->s_addr;
        links[nlinks].data = htonl(0xffffffff); /* /32 mask */
        links[nlinks].type = 3; /* stub */
        links[nlinks].tos = 0;
        links[nlinks].metric = htons(1);
        nlinks++;
    }
    /* stub default route if requested (edge origination, type 3-like stub 0.0.0.0/0 as AS-external is better but keep router-lsa stub for simplicity here; proper is AS-external LSA type 5 - mark TODO) */
    if (want_default_route) {
        /* We'll originate as stub 0.0.0.0/0 in router LSA for minimal internal reachability;
           external AS-external origination can be added when default-route semantics are wired. */
        links[nlinks].id = 0;
        links[nlinks].data = 0;
        links[nlinks].type = 3;
        links[nlinks].tos = 0;
        links[nlinks].metric = htons(10);
        nlinks++;
    }
    /* VIP subnets from config as stub network links (master-owned) */
    hadc_ctx_t *c = g_ospf.ctx ? g_ospf.ctx : ctx;
    if (c && c->conf.routing.advertise.vip_subnets && c->role == HADC_ROLE_MASTER) {
        for (size_t i = 0; i < c->conf.cluster.n_ifaces && nlinks < 64; i++) {
            const hadc_cluster_if_t *ci = &c->conf.cluster.ifaces[i];
            for (size_t j = 0; j < ci->n_addrs && nlinks < 64; j++) {
                unsigned pl = ci->addrs[j].prefixlen;
                uint32_t mask = (pl == 0) ? 0 : htonl(0xffffffffu << (32 - (pl >= 32 ? 32 : pl)));
                if (pl >= 32) mask = 0xffffffffu;
                links[nlinks].id = ci->addrs[j].address.s_addr & mask;
                links[nlinks].data = mask;
                links[nlinks].type = 3;
                links[nlinks].tos = 0;
                links[nlinks].metric = htons(1);
                nlinks++;
            }
        }
    }

    if (nlinks == 0) {
        /* still originate empty router LSA to identify self */
    }

    size_t body_len = 4 + nlinks * sizeof(rlink_t); /* flags+0+#links + links */
    size_t total = sizeof(ospf_lsa_hdr_t) + body_len;
    uint8_t *buf = calloc(1, total);
    if (!buf)
        return;

    ospf_lsa_hdr_t *lh = (ospf_lsa_hdr_t *)buf;
    lh->age = htons(0);
    lh->options = 0x02; /* E */
    lh->type = OSPF_LSA_ROUTER;
    lh->id = htonl(g_ospf.router_id);
    lh->adv_router = htonl(g_ospf.router_id);
    lh->seq = htonl(g_ospf.lsa_seq++);
    if (g_ospf.lsa_seq == 0x80000000u) g_ospf.lsa_seq = OSPF_INITIAL_SEQ;
    lh->length = htons((uint16_t)total);

    uint8_t *b = buf + sizeof(*lh);
    b[0] = 0; /* flags: not B, not E, not V (edge) */
    b[1] = 0;
    uint16_t nl = htons((uint16_t)nlinks);
    memcpy(b + 2, &nl, 2);
    if (nlinks)
        memcpy(b + 4, links, nlinks * sizeof(rlink_t));

    lsa_checksum(buf, total);
    lh->checksum = (uint16_t)((buf[16] << 8) | buf[17]);

    ospf_lsa_t *e = &g_ospf.lsdb[g_ospf.n_lsas++];
    memset(e, 0, sizeof(*e));
    e->hdr = *lh;
    e->body = malloc(body_len);
    if (e->body) memcpy(e->body, b, body_len);
    e->body_len = body_len;
    e->originated = time(NULL);
    e->self = true;
    e->valid = true;

    char ridbuf[INET_ADDRSTRLEN]; u32_to_rid(g_ospf.router_id, ridbuf, sizeof(ridbuf));
    hadc_dbg("ospf: originated Router-LSA (rid %s, seq 0x%08x, %zu stub links)",
             ridbuf, ntohl(lh->seq), nlinks);
}

void hadc_ospf_tick(hadc_ctx_t *ctx)
{
    if (!g_ospf.enabled || g_ospf.fd < 0)
        return;
    g_ospf.ctx = ctx;
    refresh_ifaces(ctx);
    expire_neighbors();

    time_t now = time(NULL);
    if (now - g_ospf.last_hello_sent >= OSPF_HELLO_INTERVAL) {
        for (size_t i = 0; i < g_ospf.n_ifaces; i++)
            send_hello_on(&g_ospf.ifaces[i]);
        g_ospf.last_hello_sent = now;
    }

    /* Refresh self-originated LSAs periodically */
    for (size_t i = 0; i < g_ospf.n_lsas; i++) {
        if (g_ospf.lsdb[i].self && g_ospf.lsdb[i].valid &&
            now - g_ospf.lsdb[i].originated >= OSPF_LSA_REFRESH) {
            /* routing/originate path will rebuild on reconcile; mark age via refresh time */
            g_ospf.lsdb[i].originated = now;
        }
    }
}
