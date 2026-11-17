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
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <unistd.h>

#include "ha-dhcpc/log.h"
#include "ha-dhcpc/ipv4.h"
#include "internal.h"
#include <jansson.h>
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
#define OSPF_MAX_LSRX 64
#define OSPF_MAX_LSREQ 64
#define OSPF_RXMT_INTERVAL 5

#define HADC_OSPF_MAX_LEARNED_ROUTES 128

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
    time_t last_sent;
    bool in_use;
} ospf_lsrx_t;

typedef struct {
    uint8_t type;
    uint32_t id;
    uint32_t adv_router;
    time_t last_sent;
    bool in_use;
} ospf_lsreq_t;


typedef struct {
    uint32_t router_id; /* host order */
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
    bool lsa_sync_sent;
    unsigned ifindex;
    /* DBD/LSR/LSA exchange state */
    uint32_t dd_seq;
    uint32_t dd_last_recv_seq;
    bool dd_master;
    bool dd_last_sent_init;
    time_t last_dbdesc_sent;
    time_t last_lsreq_sent;
    uint8_t last_dbd[OSPF_MTU];
    size_t last_dbd_len;
    uint8_t last_dbd_flags;
    bool last_dbd_has_headers;
    ospf_lsrx_t ls_rxmt[OSPF_MAX_LSRX];
    size_t n_ls_rxmt;
    ospf_lsreq_t ls_req[OSPF_MAX_LSREQ];
    size_t n_ls_req;
} ospf_neighbor_t;


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
    time_t last_self_orig;
    uint32_t last_orig_hash;
    int last_role;    /* role at last origination; a role change bypasses the
                       * hash gate so promotion/demotion refloods immediately */
    time_t start_time; /* for the post-startup LSA grace window */
    hadc_ctx_t *ctx;
    pthread_mutex_t lock; /* guards g_ospf; held across RX/tick/FSM/LSDB/SPF on the
                           * OSPF thread and across the main-loop entry points */
    pthread_t thread;
    bool thread_started;
    int pipe[2]; /* [0] read by the poll loop, [1] written by shutdown to wake it */
    volatile sig_atomic_t stop; /* set by shutdown to end the poll loop */
} ospf_state_t;

static ospf_state_t g_ospf;

/* Guards g_ospf. The OSPF thread holds it across RX/tick/FSM/LSDB/SPF; the
 * main-loop entry points (originate/default_candidates/learned_routes/status/
 * shutdown) hold it across their critical sections. Keep critical sections tight
 * and never lock across a call that itself locks. */
#define OSPF_LOCK()   pthread_mutex_lock(&g_ospf.lock)
#define OSPF_UNLOCK() pthread_mutex_unlock(&g_ospf.lock)

#define OSPF_TICK_MS 1000 /* poll timeout == the tick cadence the main loop used */

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

static bool lsa_checksum_ok(const uint8_t *lsa, size_t len)
{
    if (len < 18)
        return false;
    uint8_t tmp[OSPF_MTU];
    if (len > sizeof(tmp))
        return false;
    memcpy(tmp, lsa, len);
    uint16_t old = (uint16_t)((tmp[16] << 8) | tmp[17]);
    uint16_t calc = lsa_checksum(tmp, len);
    return old == calc;
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

static void ospf_drain_rx_locked(void);
static void ospf_tick_locked(void);
static void *ospf_thread_main(void *arg);

static void refresh_ifaces(hadc_ctx_t *ctx)
{
    struct ifaddrs *ifas = NULL, *ifa;
    ospf_if_t prev[OSPF_MAX_IFACES];
    size_t n_prev = g_ospf.n_ifaces;

    memcpy(prev, g_ospf.ifaces, sizeof(prev));

    g_ospf.n_ifaces = 0;
    for (size_t i = 0; i < ctx->conf.ospf.n_interfaces && g_ospf.n_ifaces < OSPF_MAX_IFACES; i++) {
        ospf_if_t *oi = &g_ospf.ifaces[g_ospf.n_ifaces];
        memset(oi, 0, sizeof(*oi));
        snprintf(oi->name, sizeof(oi->name), "%s", ctx->conf.ospf.interfaces[i]);
        for (size_t j = 0; j < n_prev; j++) {
            if (prev[j].name[0] && strcmp(prev[j].name, oi->name) == 0 && prev[j].ifindex != 0) {
                oi->ifindex = prev[j].ifindex;
                break;
            }
        }
        if (!oi->ifindex)
            oi->ifindex = if_nametoindex(oi->name);
        if (oi->ifindex)
            g_ospf.n_ifaces++;
    }

    if (g_ospf.n_ifaces == 0)
        return;
    if (getifaddrs(&ifas) != 0)
        return;

    for (size_t i = 0; i < g_ospf.n_ifaces; i++) {
        ospf_if_t *oi = &g_ospf.ifaces[i];
        oi->up = false;
        oi->addr.s_addr = 0;
        oi->mask.s_addr = 0;
        oi->network.s_addr = 0;
        for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
                continue;
            if (strcmp(ifa->ifa_name, oi->name) != 0)
                continue;
            oi->addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            if (ifa->ifa_netmask)
                oi->mask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr;
            oi->up = true;
            oi->network.s_addr = oi->addr.s_addr & oi->mask.s_addr;
            break;
        }
    }
    freeifaddrs(ifas);
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
    g_ospf.start_time = time(NULL);
    /* Startup restore: re-adopt persisted self LSAs exactly (sequence and age
     * continue); the reconcile grace window then holds them so a daemon
     * restart never moves the LSDB or the routes learned from it. */
    if (ctx->persist_ospf_seq)
        g_ospf.lsa_seq = (uint32_t)ctx->persist_ospf_seq;
    json_t *saved = (json_t *)ctx->persist_ospf_lsas;
    if (saved && json_is_array(saved)) {
        json_t *e;
        size_t idx;
        json_array_foreach(saved, idx, e) {
            if (!json_is_object(e) || g_ospf.n_lsas >= OSPF_MAX_LSAS)
                break;
            json_t *jt = json_object_get(e, "type"), *ji = json_object_get(e, "id"),
                   *js = json_object_get(e, "seq"), *ja = json_object_get(e, "age"),
                   *jb = json_object_get(e, "body_hex");
            if (!jt || !ji || !js || !ja || !jb || !json_is_string(jb))
                continue;
            const char *hx = json_string_value(jb);
            size_t blen = strlen(hx) / 2;
            if (blen > OSPF_MTU)
                break;
            ospf_lsa_t *ls = &g_ospf.lsdb[g_ospf.n_lsas];
            memset(ls, 0, sizeof(*ls));
            ls->hdr.type = (uint8_t)json_integer_value(jt);
            ls->hdr.id = htonl((uint32_t)json_integer_value(ji));
            ls->hdr.seq = htonl((uint32_t)json_integer_value(js));
            ls->hdr.age = htons((uint16_t)json_integer_value(ja));
            ls->hdr.options = 0x02; /* E */
            ls->hdr.adv_router = htonl(g_ospf.router_id);
            if (blen) {
                ls->body = malloc(blen);
                if (!ls->body)
                    break;
                for (size_t k = 0; k < blen; k++) {
                    unsigned b;
                    if (sscanf(hx + 2 * k, "%2x", &b) != 1) {
                        free(ls->body);
                        ls->body = NULL;
                        blen = 0;
                        break;
                    }
                    ls->body[k] = (uint8_t)b;
                }
            }
            ls->body_len = blen;
            ls->hdr.length = htons((uint16_t)(sizeof(ospf_lsa_hdr_t) + blen));
            uint8_t full[OSPF_MTU];
            memcpy(full, &ls->hdr, sizeof(ls->hdr));
            if (blen)
                memcpy(full + sizeof(ls->hdr), ls->body, blen);
            lsa_checksum(full, sizeof(ls->hdr) + blen);
            ls->hdr.checksum = (uint16_t)((full[16] << 8) | full[17]);
            ls->originated = time(NULL) - (time_t)json_integer_value(ja);
            ls->self = true;
            ls->valid = true;
            g_ospf.n_lsas++;
        }
    }
    g_ospf.pipe[0] = g_ospf.pipe[1] = -1;
    if (pthread_mutex_init(&g_ospf.lock, NULL) != 0) {
        g_ospf.enabled = false;
        return 0;
    }
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
        {
            char abuf[INET_ADDRSTRLEN];
            hadc_info("ospf: interface %s idx=%u addr=%s (router-id %s)",
                      g_ospf.ifaces[i].name, g_ospf.ifaces[i].ifindex,
                      hadc_ipv4_format(g_ospf.ifaces[i].addr, abuf, sizeof(abuf)), ctx->conf.ospf.router_id);
        }
    }

    if (pipe2(g_ospf.pipe, O_NONBLOCK | O_CLOEXEC) != 0) {
        hadc_warn("ospf: pipe2 failed: %s", strerror(errno));
        g_ospf.pipe[0] = g_ospf.pipe[1] = -1;
    }

    if (ctx->conf.ospf.auth.type == 2)
        hadc_warn("ospf: md5 auth configured but not implemented; OSPF packets will be rejected (use plaintext or none)");

    hadc_info("ospf: started (area 0, %zu interfaces, router-id %s)",
              g_ospf.n_ifaces, ctx->conf.ospf.router_id);
    return 0;
}

void hadc_ospf_shutdown(hadc_ctx_t *ctx)
{
    (void)ctx;
    /* Stop the OSPF thread (set stop, wake its poll, join) before freeing state.
     * The mutex is left intact so a later init/spawn cycle stays valid. */
    if (g_ospf.thread_started) {
        g_ospf.stop = 1;
        if (g_ospf.pipe[1] >= 0) {
            char w = 1;
            ssize_t ignored = write(g_ospf.pipe[1], &w, 1);
            (void)ignored;
        }
        pthread_join(g_ospf.thread, NULL);
        g_ospf.thread_started = false;
    }
    /* Thread joined: sole writer, no lock needed. */
    if (g_ospf.fd >= 0) {
        close(g_ospf.fd);
        g_ospf.fd = -1;
    }
    if (g_ospf.pipe[0] >= 0) {
        close(g_ospf.pipe[0]);
        close(g_ospf.pipe[1]);
        g_ospf.pipe[0] = g_ospf.pipe[1] = -1;
    }
    for (size_t i = 0; i < g_ospf.n_lsas; i++) {
        free(g_ospf.lsdb[i].body);
        g_ospf.lsdb[i].body = NULL;
    }
    pthread_mutex_destroy(&g_ospf.lock);
    memset(&g_ospf, 0, sizeof(g_ospf));
    g_ospf.fd = -1;
    g_ospf.pipe[0] = g_ospf.pipe[1] = -1;
    pthread_mutex_init(&g_ospf.lock, NULL);
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

static void apply_auth(ospf_hdr_t *h, hadc_ctx_t *ctx, const uint8_t *pkt, size_t len)
{
    (void)pkt; (void)len;
    h->autype = 0;
    h->auth = 0;
    if (!ctx)
        return;
    if (ctx->conf.ospf.auth.type == 1) { /* plaintext (8 bytes) */
        h->autype = htons(1);
        uint8_t key[8] = {0};
        size_t klen = strnlen(ctx->conf.ospf.auth.key, sizeof(key));
        memcpy(key, ctx->conf.ospf.auth.key, klen);
        memcpy(&h->auth, key, 8);
    } else if (ctx->conf.ospf.auth.type == 2) {
        /* MD5 auth not implemented; fall back to none but log? handled elsewhere */
        h->autype = 0;
        h->auth = 0;
    }
}

static bool verify_auth(const ospf_hdr_t *h, hadc_ctx_t *ctx)
{
    if (!ctx)
        return true;
    uint16_t at = ntohs(h->autype);
    if (ctx->conf.ospf.auth.type == 0)
        return at == 0;
    if (ctx->conf.ospf.auth.type == 1) {
        if (at != 1) return false;
        uint8_t key[8] = {0};
        size_t klen = strnlen(ctx->conf.ospf.auth.key, sizeof(key));
        memcpy(key, ctx->conf.ospf.auth.key, klen);
        return memcmp(&h->auth, key, 8) == 0;
    }
    /* md5 not implemented: accept as best-effort interop? better reject to be safe */
    return false;
}

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

static void send_to(struct in_addr dst, unsigned ifindex, const uint8_t *pkt, size_t len)
{
    if (g_ospf.fd < 0 || len == 0)
        return;
    struct sockaddr_in da;
    memset(&da, 0, sizeof(da));
    da.sin_family = AF_INET;
    da.sin_addr = dst;

    if (ifindex) {
        for (size_t i = 0; i < g_ospf.n_ifaces; i++) {
            if (g_ospf.ifaces[i].ifindex == ifindex && g_ospf.ifaces[i].up) {
                static unsigned last_ifindex;
                static uint32_t last_addr;
                if (last_ifindex != ifindex || last_addr != g_ospf.ifaces[i].addr.s_addr) {
                    struct ip_mreqn mreq;
                    memset(&mreq, 0, sizeof(mreq));
                    mreq.imr_address = g_ospf.ifaces[i].addr;
                    mreq.imr_ifindex = (int)ifindex;
                    (void)setsockopt(g_ospf.fd, IPPROTO_IP, IP_MULTICAST_IF, &mreq, sizeof(mreq));
                    last_ifindex = ifindex;
                    last_addr = g_ospf.ifaces[i].addr.s_addr;
                }
                break;
            }
        }
    }
    ssize_t n = sendto(g_ospf.fd, pkt, len, 0, (struct sockaddr *)&da, sizeof(da));
    if (n < 0) {
        char dbuf[INET_ADDRSTRLEN];
        hadc_dbg("ospf: send to %s failed: %s", hadc_ipv4_format(dst, dbuf, sizeof(dbuf)), strerror(errno));
    }
}

static void send_allspfrouters(const uint8_t *pkt, size_t len)
{
    struct in_addr dst;
    if (inet_pton(AF_INET, OSPF_ALLSPFROUTERS, &dst) != 1)
        return;
    for (size_t i = 0; i < g_ospf.n_ifaces; i++) {
        if (g_ospf.ifaces[i].up && g_ospf.ifaces[i].ifindex)
            send_to(dst, g_ospf.ifaces[i].ifindex, pkt, len);
    }
}

/* Effective LSA age now (stored age at last refresh + time since). */
static uint32_t lsa_effective_age(const ospf_lsa_t *e)
{
    return (uint32_t)ntohs(e->hdr.age) + (uint32_t)(time(NULL) - e->originated);
}

static bool lsa_same(const ospf_lsa_hdr_t *a, const ospf_lsa_hdr_t *b)
{
    return a->type == b->type && a->id == b->id && a->adv_router == b->adv_router;
}

static bool lsa_more_recent(const ospf_lsa_hdr_t *a, const ospf_lsa_hdr_t *b)
{
    int32_t sa = (int32_t)ntohl(a->seq);
    int32_t sb = (int32_t)ntohl(b->seq);
    if (sa != sb)
        return sa > sb;
    if (a->checksum != b->checksum)
        return ntohs(a->checksum) > ntohs(b->checksum);
    uint16_t aa = ntohs(a->age) == OSPF_LSA_MAXAGE ? OSPF_LSA_MAXAGE : 0;
    uint16_t ab = ntohs(b->age) == OSPF_LSA_MAXAGE ? OSPF_LSA_MAXAGE : 0;
    if (aa != ab)
        return aa > ab;
    return false;
}

static ospf_lsa_t *find_lsa(const ospf_lsa_hdr_t *h)
{
    for (size_t i = 0; i < g_ospf.n_lsas; i++) {
        if (g_ospf.lsdb[i].valid && lsa_same(&g_ospf.lsdb[i].hdr, h))
            return &g_ospf.lsdb[i];
    }
    return NULL;
}

static void remove_lsa_at(size_t i)
{
    free(g_ospf.lsdb[i].body);
    g_ospf.lsdb[i] = g_ospf.lsdb[--g_ospf.n_lsas];
}

static bool install_lsa(const uint8_t *lsapkt, size_t lsalen)
{
    if (lsalen < sizeof(ospf_lsa_hdr_t))
        return false;
    const ospf_lsa_hdr_t *h = (const ospf_lsa_hdr_t *)lsapkt;
    uint16_t len = ntohs(h->length);
    if (len < sizeof(*h) || len > lsalen)
        return false;

    bool is_self = (ntohl(h->adv_router) == g_ospf.router_id);
    bool maxage = (ntohs(h->age) == OSPF_LSA_MAXAGE);
    ospf_lsa_t *old = find_lsa(h);

    /* If we receive a newer instance of our own LSA, advance seq on next originate */
    if (is_self) {
        if (!old)
            return false;
        if (lsa_more_recent(h, &old->hdr)) {
            uint32_t seq = ntohl(h->seq);
            if (seq >= g_ospf.lsa_seq)
                g_ospf.lsa_seq = seq + 1;
            /* force reoriginate soon */
            g_ospf.last_orig_hash = 0;
        }
        return false;
    }

    if (old) {
        if (!lsa_more_recent(h, &old->hdr) && ntohl(h->seq) == ntohl(old->hdr.seq) &&
            h->checksum == old->hdr.checksum && ntohs(h->age) == ntohs(old->hdr.age))
            return false; /* duplicate */
        free(old->body);
        old->body = NULL;
        old->valid = false;
    } else {
        if (maxage)
            return false; /* do not install unknown MaxAge */
        if (g_ospf.n_lsas >= OSPF_MAX_LSAS)
            return false;
        old = &g_ospf.lsdb[g_ospf.n_lsas++];
        memset(old, 0, sizeof(*old));
    }

    if (maxage) {
        /* remove learned MaxAge LSA */
        for (size_t i = 0; i < g_ospf.n_lsas; i++) {
            if (&g_ospf.lsdb[i] == old) { remove_lsa_at(i); break; }
        }
        return true;
    }

    size_t body_len = len - sizeof(*h);
    old->hdr = *h;
    old->body = body_len ? malloc(body_len) : NULL;
    if (body_len && old->body)
        memcpy(old->body, lsapkt + sizeof(*h), body_len);
    old->body_len = body_len;
    old->originated = time(NULL);
    old->self = false;
    old->valid = true;

    char rid[INET_ADDRSTRLEN]; u32_to_rid(ntohl(h->adv_router), rid, sizeof(rid));
    hadc_dbg("ospf: LSDB install type=%u id=%08x adv=%s seq=0x%08x", h->type,
             ntohl(h->id), rid, ntohl(h->seq));
    return true;
}


static bool lsrx_same(const ospf_lsa_hdr_t *a, const ospf_lsa_hdr_t *b)
{
    return lsa_same(a, b);
}

static void nbr_clear_lsreq(ospf_neighbor_t *n)
{
    n->n_ls_req = 0;
    memset(n->ls_req, 0, sizeof(n->ls_req));
}

static void nbr_clear_lsrx(ospf_neighbor_t *n)
{
    n->n_ls_rxmt = 0;
    memset(n->ls_rxmt, 0, sizeof(n->ls_rxmt));
}

static void nbr_reset_exchange(ospf_neighbor_t *n)
{
    nbr_clear_lsreq(n);
    nbr_clear_lsrx(n);
    n->last_dbd_len = 0;
    n->last_dbd_has_headers = false;
    n->dd_last_recv_seq = 0;
}

static void nbr_lsrx_add(ospf_neighbor_t *n, const ospf_lsa_hdr_t *h)
{
    for (size_t i = 0; i < OSPF_MAX_LSRX; i++) {
        if (n->ls_rxmt[i].in_use && lsrx_same(&n->ls_rxmt[i].hdr, h)) {
            n->ls_rxmt[i].hdr = *h;
            n->ls_rxmt[i].last_sent = time(NULL);
            return;
        }
    }
    for (size_t i = 0; i < OSPF_MAX_LSRX; i++) {
        if (!n->ls_rxmt[i].in_use) {
            n->ls_rxmt[i].in_use = true;
            n->ls_rxmt[i].hdr = *h;
            n->ls_rxmt[i].last_sent = time(NULL);
            n->n_ls_rxmt++;
            return;
        }
    }
}

static void nbr_lsrx_ack(ospf_neighbor_t *n, const ospf_lsa_hdr_t *ack)
{
    for (size_t i = 0; i < OSPF_MAX_LSRX; i++) {
        if (!n->ls_rxmt[i].in_use) continue;
        if (!lsrx_same(&n->ls_rxmt[i].hdr, ack)) continue;
        /* ack is sufficient if not older than what we have on rxmt list */
        if (!lsa_more_recent(&n->ls_rxmt[i].hdr, ack)) {
            n->ls_rxmt[i].in_use = false;
            if (n->n_ls_rxmt) n->n_ls_rxmt--;
        }
        return;
    }
}

static void nbr_lsreq_add(ospf_neighbor_t *n, const ospf_lsa_hdr_t *h)
{
    for (size_t i = 0; i < OSPF_MAX_LSREQ; i++) {
        if (n->ls_req[i].in_use && n->ls_req[i].type == h->type &&
            n->ls_req[i].id == h->id && n->ls_req[i].adv_router == h->adv_router)
            return;
    }
    for (size_t i = 0; i < OSPF_MAX_LSREQ; i++) {
        if (!n->ls_req[i].in_use) {
            n->ls_req[i].in_use = true;
            n->ls_req[i].type = h->type;
            n->ls_req[i].id = h->id;
            n->ls_req[i].adv_router = h->adv_router;
            n->ls_req[i].last_sent = 0;
            n->n_ls_req++;
            return;
        }
    }
}

static void nbr_lsreq_remove(ospf_neighbor_t *n, const ospf_lsa_hdr_t *h)
{
    for (size_t i = 0; i < OSPF_MAX_LSREQ; i++) {
        if (!n->ls_req[i].in_use) continue;
        if (n->ls_req[i].type == h->type && n->ls_req[i].id == h->id &&
            n->ls_req[i].adv_router == h->adv_router) {
            n->ls_req[i].in_use = false;
            if (n->n_ls_req) n->n_ls_req--;
            return;
        }
    }
}

static bool nbr_has_lsreq(ospf_neighbor_t *n)
{
    for (size_t i = 0; i < OSPF_MAX_LSREQ; i++)
        if (n->ls_req[i].in_use) return true;
    return false;
}


static void build_lsack(const ospf_lsa_hdr_t *hdrs, size_t count, uint8_t *buf, size_t *outlen)
{
    memset(buf, 0, OSPF_MTU);
    ospf_hdr_t *h = (ospf_hdr_t *)buf;
    h->version = OSPF_VERSION;
    h->type = OSPF_LSACK;
    h->router_id = htonl(g_ospf.router_id);
    h->area_id = htonl(OSPF_AREA_BACKBONE);
    size_t off = sizeof(*h);
    for (size_t i = 0; i < count && off + sizeof(ospf_lsa_hdr_t) <= OSPF_MTU; i++) {
        memcpy(buf + off, &hdrs[i], sizeof(ospf_lsa_hdr_t));
        off += sizeof(ospf_lsa_hdr_t);
    }
    h->length = htons((uint16_t)off);
    apply_auth(h, g_ospf.ctx, buf, off);
    h->checksum = 0;
    h->checksum = ip_checksum(buf, off);
    *outlen = off;
}

static size_t lsa_wire_len(ospf_lsa_t *e)
{
    if (!e || !e->valid) return 0;
    size_t l = ntohs(e->hdr.length);
    if (l < sizeof(ospf_lsa_hdr_t) || l != sizeof(ospf_lsa_hdr_t) + e->body_len)
        l = sizeof(ospf_lsa_hdr_t) + e->body_len;
    return l;
}

static void build_lsupdate(uint8_t *buf, size_t *outlen, bool self_only)
{
    memset(buf, 0, OSPF_MTU);
    ospf_hdr_t *h = (ospf_hdr_t *)buf;
    h->version = OSPF_VERSION;
    h->type = OSPF_LSUPDATE;
    h->router_id = htonl(g_ospf.router_id);
    h->area_id = htonl(OSPF_AREA_BACKBONE);
    size_t off = sizeof(*h) + 4; /* + #lsas */
    uint32_t nlsas = 0;
    for (size_t i = 0; i < g_ospf.n_lsas; i++) {
        ospf_lsa_t *e = &g_ospf.lsdb[i];
        if (!e->valid)
            continue;
        if (self_only && !e->self)
            continue;
        size_t l = lsa_wire_len(e);
        if (off + l > OSPF_MTU)
            continue; /* try to fit smaller ones later */
        memcpy(buf + off, &e->hdr, sizeof(e->hdr));
        if (e->body_len && e->body)
            memcpy(buf + off + sizeof(e->hdr), e->body, e->body_len);
        /* refresh age/checksum fields in packet copy */
        if (e->self)
            ((ospf_lsa_hdr_t *)(buf + off))->age = htons(0);
        lsa_checksum(buf + off, l);
        off += l;
        nlsas++;
    }
    uint32_t nl = htonl(nlsas);
    memcpy(buf + sizeof(*h), &nl, 4);
    h->length = htons((uint16_t)off);
    apply_auth(h, g_ospf.ctx, buf, off);
    h->checksum = 0;
    h->checksum = ip_checksum(buf, off);
    *outlen = off;
}

static void flood_lsas_to_neighbor(ospf_neighbor_t *n, bool self_only)
{
    uint8_t pkt[OSPF_MTU];
    size_t len = 0;
    build_lsupdate(pkt, &len, self_only);
    if (len <= sizeof(ospf_hdr_t) + 4)
        return; /* no lsas */
    /* add sent LSAs to retransmission list */
    uint32_t nlsas = 0;
    memcpy(&nlsas, pkt + sizeof(ospf_hdr_t), 4);
    nlsas = ntohl(nlsas);
    size_t off = sizeof(ospf_hdr_t) + 4;
    for (uint32_t i = 0; i < nlsas && off + sizeof(ospf_lsa_hdr_t) <= len; i++) {
        const ospf_lsa_hdr_t *lh = (const ospf_lsa_hdr_t *)(pkt + off);
        uint16_t llen = ntohs(lh->length);
        if (llen < sizeof(*lh) || off + llen > len) break;
        nbr_lsrx_add(n, lh);
        off += llen;
    }
    send_to(n->ip, n->ifindex, pkt, len);
    {
        char nbuf[INET_ADDRSTRLEN];
        hadc_dbg("ospf: sent LS Update (%s, %u lsas) to %s", self_only ? "self" : "lsdb",
                 nlsas, hadc_ipv4_format(n->ip, nbuf, sizeof(nbuf)));
    }
}

static void flood_self_lsas_to_neighbor(ospf_neighbor_t *n)
{
    flood_lsas_to_neighbor(n, true);
}



static void build_hello(uint8_t *buf, size_t *outlen, ospf_if_t *iface)
{
    memset(buf, 0, OSPF_MTU);
    ospf_hdr_t *h = (ospf_hdr_t *)buf;
    ospf_hello_t *hello = (ospf_hello_t *)(buf + sizeof(*h));
    h->version = OSPF_VERSION;
    h->type = OSPF_HELLO;
    h->router_id = htonl(g_ospf.router_id);
    h->area_id = htonl(OSPF_AREA_BACKBONE);
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
    apply_auth(h, g_ospf.ctx, buf, off);
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


#define OSPF_DD_FLAG_MS 0x01
#define OSPF_DD_FLAG_M  0x02
#define OSPF_DD_FLAG_I  0x04

typedef struct {
    uint16_t mtu;
    uint8_t options;
    uint8_t flags;
    uint32_t seq;
} __attribute__((packed)) ospf_dbdesc_t;

static void build_dbdesc(uint8_t *buf, size_t *outlen, uint8_t flags, uint32_t seq, bool include_headers)
{
    memset(buf, 0, OSPF_MTU);
    ospf_hdr_t *h = (ospf_hdr_t *)buf;
    ospf_dbdesc_t *dd = (ospf_dbdesc_t *)(buf + sizeof(*h));
    h->version = OSPF_VERSION;
    h->type = OSPF_DBDESC;
    h->router_id = htonl(g_ospf.router_id);
    h->area_id = htonl(OSPF_AREA_BACKBONE);
    dd->mtu = htons(0);
    dd->options = 0x02; /* E */
    dd->flags = flags;
    dd->seq = htonl(seq);
    size_t off = sizeof(*h) + sizeof(*dd);
    if (include_headers) {
        for (size_t i = 0; i < g_ospf.n_lsas && off + sizeof(ospf_lsa_hdr_t) <= OSPF_MTU; i++) {
            if (!g_ospf.lsdb[i].valid) continue;
            memcpy(buf + off, &g_ospf.lsdb[i].hdr, sizeof(ospf_lsa_hdr_t));
            off += sizeof(ospf_lsa_hdr_t);
        }
    }
    h->length = htons((uint16_t)off);
    apply_auth(h, g_ospf.ctx, buf, off);
    h->checksum = 0;
    h->checksum = ip_checksum(buf, off);
    *outlen = off;
}


static void nbr_send_dbdesc(ospf_neighbor_t *n, uint8_t flags, uint32_t seq, bool include_headers)
{
    uint8_t out[OSPF_MTU]; size_t olen = 0;
    build_dbdesc(out, &olen, flags, seq, include_headers);
    send_to(n->ip, n->ifindex, out, olen);
    n->last_dbdesc_sent = time(NULL);
    n->last_dbd_flags = flags;
    n->last_dbd_has_headers = include_headers;
    n->last_dbd_len = olen;
    memcpy(n->last_dbd, out, olen);
}

static void nbr_send_lsreq(ospf_neighbor_t *n)
{
    if (!nbr_has_lsreq(n))
        return;
    time_t now = time(NULL);
    bool has_unsent = false;
    for (size_t i = 0; i < OSPF_MAX_LSREQ; i++) {
        if (n->ls_req[i].in_use && n->ls_req[i].last_sent == 0) {
            has_unsent = true;
            break;
        }
    }
    if (!has_unsent && n->last_lsreq_sent != 0 && now - n->last_lsreq_sent < OSPF_RXMT_INTERVAL)
        return;
    uint8_t out[OSPF_MTU];
    memset(out, 0, sizeof(out));
    ospf_hdr_t *oh = (ospf_hdr_t *)out;
    oh->version = OSPF_VERSION; oh->type = OSPF_LSREQ;
    oh->router_id = htonl(g_ospf.router_id); oh->area_id = htonl(OSPF_AREA_BACKBONE);
    size_t ooff = sizeof(*oh);
    size_t nreq = 0;
    for (size_t i = 0; i < OSPF_MAX_LSREQ && ooff + 12 <= OSPF_MTU; i++) {
        if (!n->ls_req[i].in_use) continue;
        uint32_t t = htonl(n->ls_req[i].type), id = n->ls_req[i].id, adv = n->ls_req[i].adv_router;
        memcpy(out + ooff, &t, 4); memcpy(out + ooff + 4, &id, 4); memcpy(out + ooff + 8, &adv, 4);
        ooff += 12; nreq++;
        n->ls_req[i].last_sent = now;
    }
    if (!nreq)
        return;
    oh->length = htons((uint16_t)ooff);
    apply_auth(oh, g_ospf.ctx, out, ooff);
    oh->checksum = 0; oh->checksum = ip_checksum(out, ooff);
    send_to(n->ip, n->ifindex, out, ooff);
    n->last_lsreq_sent = now;
    {
        char nbuf[INET_ADDRSTRLEN];
        hadc_dbg("ospf: sent LS Request (%zu) to %s", nreq, hadc_ipv4_format(n->ip, nbuf, sizeof(nbuf)));
    }
}


static void send_lsreq_missing(ospf_neighbor_t *n, const uint8_t *pkt, size_t len)
{
    /* pkt is DBD; request any listed LSA headers we don't have or that are newer */
    if (len < sizeof(ospf_hdr_t) + sizeof(ospf_dbdesc_t))
        return;
    size_t off = sizeof(ospf_hdr_t) + sizeof(ospf_dbdesc_t);
    bool added = false;
    while (off + sizeof(ospf_lsa_hdr_t) <= len) {
        const ospf_lsa_hdr_t *lh = (const ospf_lsa_hdr_t *)(pkt + off);
        off += sizeof(ospf_lsa_hdr_t);
        if (ntohl(lh->adv_router) == g_ospf.router_id)
            continue;
        ospf_lsa_t *have = find_lsa(lh);
        if (have && have->valid && !lsa_more_recent(lh, &have->hdr))
            continue;
        nbr_lsreq_add(n, lh);
        added = true;
    }
    if (added) {
        if (n->state == NSTATE_EXCHANGE)
            n->state = NSTATE_LOADING;
        nbr_send_lsreq(n);
    }
}

static void handle_hello(const uint8_t *pkt, size_t len, struct in_addr src, ospf_if_t *iface)
{
    if (len < sizeof(ospf_hdr_t) + sizeof(ospf_hello_t))
        return;
    const ospf_hdr_t *h = (const ospf_hdr_t *)pkt;
    const ospf_hello_t *hello = (const ospf_hello_t *)(pkt + sizeof(*h));
    if (h->version != OSPF_VERSION || h->type != OSPF_HELLO)
        return;
    if (ntohl(h->area_id) != OSPF_AREA_BACKBONE)
        return;
    uint32_t rid = ntohl(h->router_id);
    if (rid == g_ospf.router_id)
        return; /* our own */
    if (iface) {
        if (hello->network_mask != iface->mask.s_addr)
            return;
        if (ntohs(hello->hello_interval) != OSPF_HELLO_INTERVAL)
            return;
        if (ntohl(hello->dead_interval) != OSPF_DEAD_INTERVAL)
            return;
    }

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
    n->ifindex = iface ? iface->ifindex : n->ifindex;
    n->last_hello = time(NULL);
    uint32_t dead = ntohl(hello->dead_interval);
    if (dead == 0) dead = OSPF_DEAD_INTERVAL;
    n->dead_at = n->last_hello + (time_t)dead;

    if (see_self) {
        if (n->state < NSTATE_2WAY) {
            nbr_reset_exchange(n);
            n->state = NSTATE_EXSTART;
            n->dd_seq = (uint32_t)time(NULL);
            n->dd_master = (g_ospf.router_id > n->router_id);
            uint8_t out[OSPF_MTU]; size_t olen = 0;
            uint8_t flags = OSPF_DD_FLAG_I | OSPF_DD_FLAG_M | OSPF_DD_FLAG_MS;
            build_dbdesc(out, &olen, flags, n->dd_seq, false);
            send_to(n->ip, n->ifindex, out, olen);
            n->last_dbdesc_sent = time(NULL);
            n->last_dbd_flags = flags;
            n->last_dbd_has_headers = false;
            n->last_dbd_len = olen;
            memcpy(n->last_dbd, out, olen);
        }
    } else {
        nbr_reset_exchange(n);
        n->state = NSTATE_INIT;
        n->dd_seq = 0;
        n->lsa_sync_sent = false;
    }

    if (n->state >= NSTATE_2WAY && !n->lsa_sync_sent && n->state != NSTATE_EXSTART) {
        flood_lsas_to_neighbor(n, false);
        n->lsa_sync_sent = true;
    }
    if (n->state < NSTATE_2WAY)
        n->lsa_sync_sent = false;

    if (n->state != old) {
        char ridbuf[INET_ADDRSTRLEN]; u32_to_rid(rid, ridbuf, sizeof(ridbuf));
        const char *sn = n->state == NSTATE_DOWN ? "Down" :
                         n->state == NSTATE_INIT ? "Init" :
                         n->state == NSTATE_2WAY ? "2-Way" :
                         n->state == NSTATE_EXSTART ? "ExStart" :
                         n->state == NSTATE_EXCHANGE ? "Exchange" :
                         n->state == NSTATE_LOADING ? "Loading" : "Full";
        {
            char sbuf[INET_ADDRSTRLEN];
            hadc_info("ospf: neighbor %s (%s) on %s -> %s", ridbuf, hadc_ipv4_format(src, sbuf, sizeof(sbuf)),
                      iface ? iface->name : "?", sn);
        }
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

static void handle_lsupdate(const uint8_t *pkt, size_t len, struct in_addr src, ospf_if_t *iface)
{
    if (len < sizeof(ospf_hdr_t) + 4)
        return;
    const ospf_hdr_t *h = (const ospf_hdr_t *)pkt;
    (void)h;
    uint32_t nlsas = 0;
    memcpy(&nlsas, pkt + sizeof(ospf_hdr_t), 4);
    nlsas = ntohl(nlsas);
    size_t off = sizeof(ospf_hdr_t) + 4;
    ospf_lsa_hdr_t acks[32];
    size_t nack = 0;
    bool changed = false;
    for (uint32_t i = 0; i < nlsas && off + sizeof(ospf_lsa_hdr_t) <= len; i++) {
        const ospf_lsa_hdr_t *lh = (const ospf_lsa_hdr_t *)(pkt + off);
        uint16_t llen = ntohs(lh->length);
        if (llen < sizeof(*lh) || off + llen > len)
            break;
        if (lsa_checksum_ok(pkt + off, llen)) {
            if (ntohl(lh->adv_router) != g_ospf.router_id) {
                if (install_lsa(pkt + off, llen))
                    changed = true;
            }
            if (nack < 32)
                acks[nack++] = *lh;
        } else {
            char sbuf[INET_ADDRSTRLEN];
            hadc_dbg("ospf: bad LSA checksum from %s (type %u adv %08x)", hadc_ipv4_format(src, sbuf, sizeof(sbuf)), lh->type, ntohl(lh->adv_router));
        }
        off += llen;
    }
    if (nack) {
        uint8_t ackpkt[OSPF_MTU];
        size_t alen = 0;
        build_lsack(acks, nack, ackpkt, &alen);
        /* direct ack to sender if possible, else multicast */
        if (iface && iface->ifindex)
            send_to(src, iface->ifindex, ackpkt, alen);
        else
            send_allspfrouters(ackpkt, alen);
    }
    /* remove satisfied requests from sender and advance Loading->Full */
    ospf_neighbor_t *sender = NULL;
    for (size_t ni = 0; ni < OSPF_MAX_NEIGHBORS; ni++) {
        if (g_ospf.nbrs[ni].in_use && g_ospf.nbrs[ni].ip.s_addr == src.s_addr) { sender = &g_ospf.nbrs[ni]; break; }
    }
    if (sender) {
        size_t off2 = sizeof(ospf_hdr_t) + 4;
        for (uint32_t i = 0; i < nlsas && off2 + sizeof(ospf_lsa_hdr_t) <= len; i++) {
            const ospf_lsa_hdr_t *lh = (const ospf_lsa_hdr_t *)(pkt + off2);
            uint16_t llen = ntohs(lh->length);
            if (llen < sizeof(*lh) || off2 + llen > len) break;
            nbr_lsreq_remove(sender, lh);
            off2 += llen;
        }
        if (sender->state == NSTATE_LOADING && !nbr_has_lsreq(sender)) {
            sender->state = NSTATE_FULL;
            sender->lsa_sync_sent = true;
        }
    }

    if (changed) {
        /* Flood received/newer LSAs to other neighbors and track retransmissions */
        for (size_t ni = 0; ni < OSPF_MAX_NEIGHBORS; ni++) {
            ospf_neighbor_t *nb = &g_ospf.nbrs[ni];
            if (!nb->in_use || nb->state < NSTATE_2WAY)
                continue;
            if (nb->ip.s_addr == src.s_addr)
                continue;
            /* forward full update (simple) and add LSAs to rxmt */
            size_t off3 = sizeof(ospf_hdr_t) + 4;
            for (uint32_t i = 0; i < nlsas && off3 + sizeof(ospf_lsa_hdr_t) <= len; i++) {
                const ospf_lsa_hdr_t *lh = (const ospf_lsa_hdr_t *)(pkt + off3);
                uint16_t llen = ntohs(lh->length);
                if (llen < sizeof(*lh) || off3 + llen > len) break;
                nbr_lsrx_add(nb, lh);
                off3 += llen;
            }
            send_to(nb->ip, nb->ifindex, pkt, len);
        }
        {
            char sbuf[INET_ADDRSTRLEN];
            hadc_dbg("ospf: LSDB updated/flooded from %s (%u lsas)", hadc_ipv4_format(src, sbuf, sizeof(sbuf)), nlsas);
        }
    }
}

static void handle_lsack(const uint8_t *pkt, size_t len, struct in_addr src)
{
    if (len < sizeof(ospf_hdr_t) + sizeof(ospf_lsa_hdr_t))
        return;
    ospf_neighbor_t *sender = NULL;
    for (size_t ni = 0; ni < OSPF_MAX_NEIGHBORS; ni++) {
        if (g_ospf.nbrs[ni].in_use && g_ospf.nbrs[ni].ip.s_addr == src.s_addr) { sender = &g_ospf.nbrs[ni]; break; }
    }
    if (!sender)
        return;
    size_t off = sizeof(ospf_hdr_t);
    while (off + sizeof(ospf_lsa_hdr_t) <= len) {
        const ospf_lsa_hdr_t *lh = (const ospf_lsa_hdr_t *)(pkt + off);
        nbr_lsrx_ack(sender, lh);
        off += sizeof(ospf_lsa_hdr_t);
    }
}

static void handle_lsreq(const uint8_t *pkt, size_t len, struct in_addr src, ospf_if_t *iface)
{
    if (len < sizeof(ospf_hdr_t) + 12)
        return;
    size_t off = sizeof(ospf_hdr_t);
    uint8_t out[OSPF_MTU];
    memset(out, 0, sizeof(out));
    ospf_hdr_t *oh = (ospf_hdr_t *)out;
    oh->version = OSPF_VERSION;
    oh->type = OSPF_LSUPDATE;
    oh->router_id = htonl(g_ospf.router_id);
    oh->area_id = htonl(OSPF_AREA_BACKBONE);
    size_t ooff = sizeof(ospf_hdr_t) + 4;
    uint32_t nlsas = 0;
    while (off + 12 <= len) {
        uint32_t type, id, adv;
        memcpy(&type, pkt + off, 4);
        memcpy(&id, pkt + off + 4, 4);
        memcpy(&adv, pkt + off + 8, 4);
        off += 12;
        ospf_lsa_hdr_t key = {0};
        key.type = (uint8_t)ntohl(type);
        key.id = id;
        key.adv_router = adv;
        ospf_lsa_t *e = find_lsa(&key);
        if (!e || !e->valid)
            continue;
        size_t l = sizeof(ospf_lsa_hdr_t) + e->body_len;
        if (ooff + l > OSPF_MTU)
            break;
        memcpy(out + ooff, &e->hdr, sizeof(e->hdr));
        if (e->body_len && e->body)
            memcpy(out + ooff + sizeof(e->hdr), e->body, e->body_len);
        lsa_checksum(out + ooff, l);
        ooff += l;
        nlsas++;
    }
    if (!nlsas)
        return;
    uint32_t nl = htonl(nlsas);
    memcpy(out + sizeof(ospf_hdr_t), &nl, 4);
    oh->length = htons((uint16_t)ooff);
    apply_auth(oh, g_ospf.ctx, out, ooff);
    oh->checksum = 0;
    oh->checksum = ip_checksum(out, ooff);
    if (iface && iface->ifindex)
        send_to(src, iface->ifindex, out, ooff);
    else
        send_to(src, 0, out, ooff);
    {
        char sbuf[INET_ADDRSTRLEN];
        hadc_dbg("ospf: replied LS Update with %u LSA(s) to LS Request from %s", nlsas, hadc_ipv4_format(src, sbuf, sizeof(sbuf)));
    }
}


static void handle_dbdesc(const uint8_t *pkt, size_t len, struct in_addr src, ospf_if_t *iface)
{
    if (len < sizeof(ospf_hdr_t) + sizeof(ospf_dbdesc_t))
        return;
    const ospf_dbdesc_t *dd = (const ospf_dbdesc_t *)(pkt + sizeof(ospf_hdr_t));
    ospf_neighbor_t *n = NULL;
    for (size_t i = 0; i < OSPF_MAX_NEIGHBORS; i++) {
        if (g_ospf.nbrs[i].in_use && g_ospf.nbrs[i].ip.s_addr == src.s_addr) { n = &g_ospf.nbrs[i]; break; }
    }
    if (!n) return;
    n->ifindex = iface ? iface->ifindex : n->ifindex;
    uint8_t flags = dd->flags;
    uint32_t seq = ntohl(dd->seq);

    if (n->state < NSTATE_2WAY) {
        flood_self_lsas_to_neighbor(n);
        return;
    }

    /* Initial DBD from peer claiming master. The election is decided by
     * router-ID: only the loser adopts the peer as master here; the winner
     * stays master and drives the exchange from the negotiation below, so
     * both sides can never end up adopting each other and looping. */
    if ((flags & OSPF_DD_FLAG_I) && (flags & OSPF_DD_FLAG_M) && (flags & OSPF_DD_FLAG_MS) &&
        g_ospf.router_id < n->router_id) {
        nbr_reset_exchange(n);
        n->state = NSTATE_EXCHANGE;
        n->dd_master = false;
        n->dd_seq = seq;
        send_lsreq_missing(n, pkt, len);
        nbr_send_dbdesc(n, 0, seq, true);
        if (!nbr_has_lsreq(n)) {
            n->state = NSTATE_FULL;
            n->lsa_sync_sent = true;
        } else {
            n->state = NSTATE_LOADING;
        }
        return;
    }

    /* ExStart negotiation: determine master/slave when both sent initial */
    if (n->state == NSTATE_EXSTART) {
        if (!(flags & OSPF_DD_FLAG_I) && !(flags & OSPF_DD_FLAG_MS) && seq == n->dd_seq &&
            g_ospf.router_id > n->router_id) {
            /* peer accepted us as master */
            n->dd_master = true;
            n->state = NSTATE_EXCHANGE;
            n->dd_last_recv_seq = seq;
            send_lsreq_missing(n, pkt, len);
            nbr_send_dbdesc(n, OSPF_DD_FLAG_MS, n->dd_seq, true);
            if (!(flags & OSPF_DD_FLAG_M) && !nbr_has_lsreq(n)) {
                n->state = NSTATE_FULL;
                n->lsa_sync_sent = true;
            } else if (!(flags & OSPF_DD_FLAG_M)) {
                n->state = NSTATE_LOADING;
            }
            return;
        } else if (!(flags & OSPF_DD_FLAG_I) && (flags & OSPF_DD_FLAG_MS) &&
                   g_ospf.router_id < n->router_id) {
            /* peer is master */
            n->dd_master = false;
            n->dd_seq = seq;
            n->state = NSTATE_EXCHANGE;
            /* fall through to exchange handling as slave receiving master's DBD */
        } else {
            /* negotiation mismatch/duplicate; retransmit handled by timer */
            return;
        }
    }

    if (n->state == NSTATE_EXCHANGE || n->state == NSTATE_LOADING) {
        /* duplicate: retransmit on timer, not per packet */
        if (seq == n->dd_last_recv_seq)
            return;

        send_lsreq_missing(n, pkt, len);
        n->dd_last_recv_seq = seq;

        if (n->dd_master) {
            /* master expects slave ack with our seq */
            if (seq != n->dd_seq) {
                /* sequence mismatch; ignore for simplicity */
                return;
            }
            if (!(flags & OSPF_DD_FLAG_M)) {
                if (!nbr_has_lsreq(n)) {
                    n->state = NSTATE_FULL;
                    n->lsa_sync_sent = true;
                } else {
                    n->state = NSTATE_LOADING;
                }
            } else {
                n->dd_seq++;
                nbr_send_dbdesc(n, OSPF_DD_FLAG_MS, n->dd_seq, true);
                n->state = nbr_has_lsreq(n) ? NSTATE_LOADING : NSTATE_EXCHANGE;
            }
        } else {
            /* slave: reply echoing peer seq; we send our full summary in one DBD (M=0) */
            nbr_send_dbdesc(n, 0, seq, true);
            if (!(flags & OSPF_DD_FLAG_M) && !nbr_has_lsreq(n)) {
                n->state = NSTATE_FULL;
                n->lsa_sync_sent = true;
            } else if (!(flags & OSPF_DD_FLAG_M)) {
                n->state = NSTATE_LOADING;
            } else {
                n->state = nbr_has_lsreq(n) ? NSTATE_LOADING : NSTATE_EXCHANGE;
            }
        }
        return;
    }

    if (n->state == NSTATE_FULL) {
        /* Duplicates are ignored (retransmit on timer). Non-duplicate DBD in
         * Full is a sequence mismatch: restart adjacency. */
        if (seq == n->dd_last_recv_seq)
            return;
        nbr_reset_exchange(n);
        n->state = NSTATE_EXSTART;
        n->dd_seq = (uint32_t)time(NULL);
        n->dd_master = (g_ospf.router_id > n->router_id);
        nbr_send_dbdesc(n, OSPF_DD_FLAG_I | OSPF_DD_FLAG_M | OSPF_DD_FLAG_MS, n->dd_seq, false);
        return;
    }

    flood_self_lsas_to_neighbor(n);
}

static void ospf_drain_rx_locked(void)
{
    uint8_t buf[2048];
    for (;;) {
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        ssize_t n = recvfrom(g_ospf.fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &slen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                break;
            break;
        }
        if (n < (ssize_t)sizeof(struct iphdr))
            continue;
        const struct iphdr *ip = (const struct iphdr *)buf;
        size_t ihl = (size_t)ip->ihl * 4;
        if (ihl < sizeof(struct iphdr) || (size_t)n < ihl + sizeof(ospf_hdr_t))
            continue;
        const uint8_t *pkt = buf + ihl;
        size_t pktlen = (size_t)n - ihl;
        const ospf_hdr_t *h = (const ospf_hdr_t *)pkt;
        if (h->version != OSPF_VERSION)
            continue;
        uint16_t plen = ntohs(h->length);
        if (plen < sizeof(ospf_hdr_t) || plen > pktlen)
            continue;
        if (ntohl(h->area_id) != OSPF_AREA_BACKBONE)
            continue;
        if (!verify_auth(h, g_ospf.ctx)) {
            char sbuf[INET_ADDRSTRLEN];
            hadc_dbg("ospf: auth mismatch from %s, dropping", hadc_ipv4_format(src.sin_addr, sbuf, sizeof(sbuf)));
            continue;
        }
        ospf_if_t *iface = iface_for_src(src.sin_addr);
        switch (h->type) {
        case OSPF_HELLO:
            handle_hello(pkt, (size_t)plen, src.sin_addr, iface);
            break;
        case OSPF_LSUPDATE:
            handle_lsupdate(pkt, (size_t)plen, src.sin_addr, iface);
            break;
        case OSPF_LSACK:
            handle_lsack(pkt, (size_t)plen, src.sin_addr);
            break;
        case OSPF_LSREQ:
            handle_lsreq(pkt, (size_t)plen, src.sin_addr, iface);
            break;
        case OSPF_DBDESC:
            handle_dbdesc(pkt, (size_t)plen, src.sin_addr, iface);
            {
                char sbuf[INET_ADDRSTRLEN];
                hadc_dbg("ospf: rx DBD from %s on %s (len %u)", hadc_ipv4_format(src.sin_addr, sbuf, sizeof(sbuf)),
                         iface ? iface->name : "?", plen);
            }
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
            char ridbuf[INET_ADDRSTRLEN], nbuf[INET_ADDRSTRLEN];
            u32_to_rid(n->router_id, ridbuf, sizeof(ridbuf));
            hadc_info("ospf: neighbor %s (%s) dead -> Down", ridbuf, hadc_ipv4_format(n->ip, nbuf, sizeof(nbuf)));
            nbr_reset_exchange(n);
            n->in_use = false;
            n->state = NSTATE_DOWN;
        }
    }
}

/* ---- self-originated Router LSA ---- */


static uint32_t orig_hash(bool want_pub, struct in_addr pub, bool want_def, hadc_ctx_t *c)
{
    uint32_t h = 2166136261u;
    #define FNV(x) do { h ^= (uint32_t)(x); h *= 16777619u; } while(0)
    FNV(want_pub);
    FNV(pub.s_addr);
    FNV(want_def);
    if (c && c->conf.routing.advertise.vip_subnets && (c->role == HADC_ROLE_MASTER || c->role == HADC_ROLE_PROMOTING)) {
        for (size_t i = 0; i < c->conf.cluster.n_ifaces; i++) {
            const hadc_cluster_if_t *ci = &c->conf.cluster.ifaces[i];
            for (size_t j = 0; j < ci->n_addrs; j++) {
                unsigned pl = ci->addrs[j].prefixlen;
                uint32_t mask = hadc_ipv4_prefix_mask(pl).s_addr;
                FNV(ci->addrs[j].address.s_addr & mask);
                FNV(mask);
            }
        }
    }
    #undef FNV
    return h;
}


static void ospf_originate_locked(hadc_ctx_t *ctx,
                                  const struct in_addr *public_ip32, bool want_pub,
                                  bool want_default_route,
                                  const void *vip_prefixes, size_t vip_prefix_count)
{
    (void)vip_prefixes; (void)vip_prefix_count;
    if (!g_ospf.enabled)
        return;
    g_ospf.ctx = ctx;

    struct in_addr pub = public_ip32 ? *public_ip32 : (struct in_addr){0};
    if (!want_pub) pub.s_addr = 0;
    uint32_t h = orig_hash(want_pub, pub, want_default_route, ctx);
    time_t now = time(NULL);
    bool refresh = (g_ospf.last_self_orig != 0 && now - g_ospf.last_self_orig >= OSPF_LSA_REFRESH);
    bool role_changed = ctx && (int)ctx->role != g_ospf.last_role;
    if (h == g_ospf.last_orig_hash && !refresh && !role_changed)
        return;

    /* Grace window (startup restore or graceful restart active): hold the LSDB
     * exactly as restored; no rebuild, no flush of withdrawn self LSAs — a
     * daemon restart must not move the LSDB or the routes learned from it. */
    if (ctx && (hadc_cluster_graceful_active(ctx) ||
                (ctx->conf.ospf.grace_period_s > 0 &&
                 now - g_ospf.start_time < (time_t)ctx->conf.ospf.grace_period_s)))
        return;

    /* Snapshot current self LSAs to detect withdrawals (flush as MaxAge). */
    ospf_lsa_t old_self[OSPF_MAX_LSAS];
    size_t n_old_self = 0;
    for (size_t i = 0; i < g_ospf.n_lsas && n_old_self < OSPF_MAX_LSAS; i++) {
        if (g_ospf.lsdb[i].valid && g_ospf.lsdb[i].self) {
            old_self[n_old_self] = g_ospf.lsdb[i];
            old_self[n_old_self].body = NULL;
            if (g_ospf.lsdb[i].body_len && g_ospf.lsdb[i].body) {
                old_self[n_old_self].body = malloc(g_ospf.lsdb[i].body_len);
                if (old_self[n_old_self].body)
                    memcpy(old_self[n_old_self].body, g_ospf.lsdb[i].body, g_ospf.lsdb[i].body_len);
                else
                    old_self[n_old_self].body_len = 0;
            }
            n_old_self++;
        }
    }

    /* Build a single self Router-LSA with stub links for originated prefixes. */
    /* remove self from lsdb (bodies freed); snapshots above own copies */
    for (size_t i = 0; i < g_ospf.n_lsas; ) {
        if (g_ospf.lsdb[i].self) {
            free(g_ospf.lsdb[i].body);
            g_ospf.lsdb[i].body = NULL;
            g_ospf.lsdb[i] = g_ospf.lsdb[--g_ospf.n_lsas];
            continue;
        }
        i++;
    }
    if (g_ospf.n_lsas >= OSPF_MAX_LSAS) {
        for (size_t i = 0; i < n_old_self; i++) free(old_self[i].body);
        return;
    }

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
    /* VIP subnets from config as stub network links (master-owned) */
    hadc_ctx_t *c = g_ospf.ctx ? g_ospf.ctx : ctx;
    if (c && c->conf.routing.advertise.vip_subnets && (c->role == HADC_ROLE_MASTER || c->role == HADC_ROLE_PROMOTING)) {
        for (size_t i = 0; i < c->conf.cluster.n_ifaces && nlinks < 64; i++) {
            const hadc_cluster_if_t *ci = &c->conf.cluster.ifaces[i];
            for (size_t j = 0; j < ci->n_addrs && nlinks < 64; j++) {
                unsigned pl = ci->addrs[j].prefixlen;
                uint32_t mask = hadc_ipv4_prefix_mask(pl).s_addr;
                links[nlinks].id = ci->addrs[j].address.s_addr & mask;
                links[nlinks].data = mask;
                links[nlinks].type = 3;
                links[nlinks].tos = 0;
                links[nlinks].metric = htons(1);
                nlinks++;
            }
        }
    }

    /* Router LSA (always originate to identify self) */
    {
        size_t body_len = 4 + nlinks * sizeof(rlink_t);
        size_t total = sizeof(ospf_lsa_hdr_t) + body_len;
        uint8_t *buf = calloc(1, total);
        if (buf && g_ospf.n_lsas < OSPF_MAX_LSAS) {
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
            b[0] = 0; b[1] = 0;
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
        }
        free(buf);
    }

    /* AS-external LSA for default route 0.0.0.0/0 (primary healthy path only). */
    if (want_default_route && g_ospf.n_lsas < OSPF_MAX_LSAS) {
        size_t body_len = 16; /* network mask + metric(E,TOS)=4 + fwd addr + ext route tag */
        size_t total = sizeof(ospf_lsa_hdr_t) + body_len;
        uint8_t *buf = calloc(1, total);
        if (buf) {
            ospf_lsa_hdr_t *lh = (ospf_lsa_hdr_t *)buf;
            lh->age = htons(0);
            lh->options = 0x02; /* E */
            lh->type = OSPF_LSA_AS_EXTERNAL;
            lh->id = 0; /* 0.0.0.0 */
            lh->adv_router = htonl(g_ospf.router_id);
            lh->seq = htonl(g_ospf.lsa_seq++);
            if (g_ospf.lsa_seq == 0x80000000u) g_ospf.lsa_seq = OSPF_INITIAL_SEQ;
            lh->length = htons((uint16_t)total);
            uint8_t *b = buf + sizeof(*lh);
            memset(b, 0, body_len);
            /* network mask 0.0.0.0 */
            uint32_t metric = htonl(0x0000000a); /* E-bit 0, metric 10 (type 1) */
            memcpy(b + 4, &metric, 4);
            /* forwarding address 0.0.0.0, tag 0 */
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
        }
        free(buf);
    }

    /* Withdraw (MaxAge) any previously self-originated LSA no longer present. */
    for (size_t i = 0; i < n_old_self; i++) {
        bool still = false;
        for (size_t j = 0; j < g_ospf.n_lsas; j++) {
            if (!g_ospf.lsdb[j].valid || !g_ospf.lsdb[j].self) continue;
            if (lsa_same(&g_ospf.lsdb[j].hdr, &old_self[i].hdr)) { still = true; break; }
        }
        if (!still) {
            /* flush with MaxAge */
            size_t l = sizeof(ospf_lsa_hdr_t) + old_self[i].body_len;
            uint8_t *pkt = calloc(1, sizeof(ospf_hdr_t) + 4 + l);
            if (pkt) {
                ospf_hdr_t *oh = (ospf_hdr_t *)pkt;
                oh->version = OSPF_VERSION; oh->type = OSPF_LSUPDATE;
                oh->router_id = htonl(g_ospf.router_id); oh->area_id = htonl(OSPF_AREA_BACKBONE);
                uint32_t nl = htonl(1);
                memcpy(pkt + sizeof(ospf_hdr_t), &nl, 4);
                uint8_t *lp = pkt + sizeof(ospf_hdr_t) + 4;
                memcpy(lp, &old_self[i].hdr, sizeof(old_self[i].hdr));
                if (old_self[i].body_len && old_self[i].body)
                    memcpy(lp + sizeof(old_self[i].hdr), old_self[i].body, old_self[i].body_len);
                ((ospf_lsa_hdr_t *)lp)->age = htons(OSPF_LSA_MAXAGE);
                ((ospf_lsa_hdr_t *)lp)->seq = old_self[i].hdr.seq;
                lsa_checksum(lp, l);
                size_t plen = sizeof(ospf_hdr_t) + 4 + l;
                oh->length = htons((uint16_t)plen);
                apply_auth(oh, g_ospf.ctx, pkt, plen);
                oh->checksum = 0; oh->checksum = ip_checksum(pkt, plen);
                for (size_t k = 0; k < OSPF_MAX_NEIGHBORS; k++) {
                    if (g_ospf.nbrs[k].in_use && g_ospf.nbrs[k].state >= NSTATE_2WAY)
                        send_to(g_ospf.nbrs[k].ip, g_ospf.nbrs[k].ifindex, pkt, plen);
                }
                hadc_info("ospf: flushed withdrawn self LSA type %u id %08x", old_self[i].hdr.type, ntohl(old_self[i].hdr.id));
                free(pkt);
            }
        }
        free(old_self[i].body);
    }

    g_ospf.last_orig_hash = h;
    g_ospf.last_self_orig = now;
    if (ctx)
        g_ospf.last_role = (int)ctx->role;

    char ridbuf[INET_ADDRSTRLEN]; u32_to_rid(g_ospf.router_id, ridbuf, sizeof(ridbuf));
    hadc_dbg("ospf: originated self LSAs (rid %s, %zu stub links, default=%s%s)",
             ridbuf, nlinks, want_default_route ? "yes" : "no",
             role_changed ? ", role change" : "");

    for (size_t i = 0; i < OSPF_MAX_NEIGHBORS; i++) {
        if (g_ospf.nbrs[i].in_use && g_ospf.nbrs[i].state >= NSTATE_2WAY)
            flood_self_lsas_to_neighbor(&g_ospf.nbrs[i]);
    }
}

void hadc_ospf_originate(hadc_ctx_t *ctx,
                         const struct in_addr *public_ip32, bool want_pub,
                         bool want_default_route,
                         const void *vip_prefixes, size_t vip_prefix_count)
{
    OSPF_LOCK();
    g_ospf.ctx = ctx;
    ospf_originate_locked(ctx, public_ip32, want_pub, want_default_route,
                          vip_prefixes, vip_prefix_count);
    OSPF_UNLOCK();
}

static void ospf_tick_locked(void)
{
    hadc_ctx_t *ctx = g_ospf.ctx;
    if (!g_ospf.enabled || g_ospf.fd < 0)
        return;

    time_t now = time(NULL);
    static time_t last_if_refresh;
    if (last_if_refresh == 0 || now != last_if_refresh) {
        refresh_ifaces(ctx);
        last_if_refresh = now;
    }
    expire_neighbors();

    if (now - g_ospf.last_hello_sent >= OSPF_HELLO_INTERVAL) {
        for (size_t i = 0; i < g_ospf.n_ifaces; i++)
            send_hello_on(&g_ospf.ifaces[i]);
        g_ospf.last_hello_sent = now;
    }

    /* Age out learned LSAs; self LSAs are refreshed by originate/reconcile. */
    for (size_t i = 0; i < g_ospf.n_lsas; ) {
        if (!g_ospf.lsdb[i].valid) { remove_lsa_at(i); continue; }
        if (!g_ospf.lsdb[i].self) {
            uint16_t age = ntohs(g_ospf.lsdb[i].hdr.age);
            unsigned adv = (unsigned)(now - g_ospf.lsdb[i].originated);
            if (age + adv >= OSPF_LSA_MAXAGE) {
                remove_lsa_at(i);
                continue;
            }
        }
        i++;
    }

    /* Periodically reflood LSAs and retransmit adjacency/LSA packets */
    static time_t last_flood, last_full_flood, last_rxmt;
    if (now - last_rxmt >= OSPF_RXMT_INTERVAL) {
        for (size_t i = 0; i < OSPF_MAX_NEIGHBORS; i++) {
            ospf_neighbor_t *n = &g_ospf.nbrs[i];
            if (!n->in_use) continue;

            /* retransmit last DBD if waiting */
            if ((n->state == NSTATE_EXSTART || n->state == NSTATE_EXCHANGE) &&
                n->last_dbd_len > 0 && now - n->last_dbdesc_sent >= OSPF_RXMT_INTERVAL) {
                send_to(n->ip, n->ifindex, n->last_dbd, n->last_dbd_len);
                n->last_dbdesc_sent = now;
            }

            /* retransmit pending LS requests */
            if ((n->state == NSTATE_EXCHANGE || n->state == NSTATE_LOADING) && nbr_has_lsreq(n) &&
                now - n->last_lsreq_sent >= OSPF_RXMT_INTERVAL) {
                nbr_send_lsreq(n);
                if (n->state == NSTATE_EXCHANGE)
                    n->state = NSTATE_LOADING;
            }

            /* retransmit unacked LSAs (simple: resend individual updates) */
            for (size_t r = 0; r < OSPF_MAX_LSRX; r++) {
                if (!n->ls_rxmt[r].in_use) continue;
                if (now - n->ls_rxmt[r].last_sent < OSPF_RXMT_INTERVAL) continue;
                ospf_lsa_t *e = find_lsa(&n->ls_rxmt[r].hdr);
                if (!e || !e->valid) { n->ls_rxmt[r].in_use = false; if (n->n_ls_rxmt) n->n_ls_rxmt--; continue; }
                /* if DB copy is newer than rxmt, update rxmt header */
                n->ls_rxmt[r].hdr = e->hdr;
                uint8_t pkt[OSPF_MTU];
                memset(pkt, 0, sizeof(pkt));
                ospf_hdr_t *oh = (ospf_hdr_t *)pkt;
                oh->version = OSPF_VERSION; oh->type = OSPF_LSUPDATE;
                oh->router_id = htonl(g_ospf.router_id); oh->area_id = htonl(OSPF_AREA_BACKBONE);
                uint32_t nl = htonl(1);
                memcpy(pkt + sizeof(*oh), &nl, 4);
                size_t l = lsa_wire_len(e);
                if (sizeof(*oh) + 4 + l > OSPF_MTU) continue;
                memcpy(pkt + sizeof(*oh) + 4, &e->hdr, sizeof(e->hdr));
                if (e->body_len && e->body)
                    memcpy(pkt + sizeof(*oh) + 4 + sizeof(e->hdr), e->body, e->body_len);
                if (e->self) ((ospf_lsa_hdr_t *)(pkt + sizeof(*oh) + 4))->age = htons(0);
                lsa_checksum(pkt + sizeof(*oh) + 4, l);
                size_t plen = sizeof(*oh) + 4 + l;
                oh->length = htons((uint16_t)plen);
                apply_auth(oh, g_ospf.ctx, pkt, plen);
                oh->checksum = 0; oh->checksum = ip_checksum(pkt, plen);
                send_to(n->ip, n->ifindex, pkt, plen);
                n->ls_rxmt[r].last_sent = now;
            }

            if (n->state == NSTATE_LOADING && !nbr_has_lsreq(n)) {
                n->state = NSTATE_FULL;
                n->lsa_sync_sent = true;
            }
            if (n->state == NSTATE_EXSTART && now - n->last_dbdesc_sent >= OSPF_RXMT_INTERVAL && n->last_dbd_len == 0) {
                nbr_send_dbdesc(n, OSPF_DD_FLAG_I | OSPF_DD_FLAG_M | OSPF_DD_FLAG_MS, n->dd_seq, false);
            }
        }
        last_rxmt = now;
    }

    if (now - last_flood >= 30) {
        for (size_t i = 0; i < OSPF_MAX_NEIGHBORS; i++) {
            if (g_ospf.nbrs[i].in_use && g_ospf.nbrs[i].state >= NSTATE_2WAY)
                flood_self_lsas_to_neighbor(&g_ospf.nbrs[i]);
        }
        last_flood = now;
    }
    if (now - last_full_flood >= 300) {
        for (size_t i = 0; i < OSPF_MAX_NEIGHBORS; i++) {
            if (g_ospf.nbrs[i].in_use && g_ospf.nbrs[i].state >= NSTATE_2WAY)
                flood_lsas_to_neighbor(&g_ospf.nbrs[i], false);
        }
        last_full_flood = now;
    }
}

void hadc_ospf_tick(hadc_ctx_t *ctx)
{
    OSPF_LOCK();
    g_ospf.ctx = ctx;
    ospf_tick_locked();
    OSPF_UNLOCK();
}


static struct in_addr nbr_nexthop_for(uint32_t adv_router)
{
    struct in_addr gw = {0};
    for (size_t ni = 0; ni < OSPF_MAX_NEIGHBORS; ni++) {
        ospf_neighbor_t *nb = &g_ospf.nbrs[ni];
        if (!nb->in_use || nb->state < NSTATE_2WAY)
            continue;
        if (nb->router_id == adv_router)
            return nb->ip;
    }
    return gw;
}

static const ospf_lsa_t *find_router_lsa(uint32_t adv_router)
{
    for (size_t i = 0; i < g_ospf.n_lsas; i++) {
        const ospf_lsa_t *e = &g_ospf.lsdb[i];
        if (!e->valid || e->hdr.type != OSPF_LSA_ROUTER)
            continue;
        if (ntohl(e->hdr.adv_router) == adv_router)
            return e;
    }
    return NULL;
}

typedef struct {
    uint32_t rid;
    uint32_t dist;
    struct in_addr nexthop;
    bool known;
    bool visited;
} spf_node_t;

static bool nexthop_on_fabric(struct in_addr nh)
{
    if (nh.s_addr == 0)
        return false;
    for (size_t i = 0; i < g_ospf.n_ifaces; i++) {
        ospf_if_t *oi = &g_ospf.ifaces[i];
        if (!oi->up || oi->mask.s_addr == 0)
            continue;
        if ((nh.s_addr & oi->mask.s_addr) == oi->network.s_addr)
            return true;
    }
    return false;
}

/* Minimal intra-area SPF (Dijkstra) over Router-LSAs to resolve nexthop to a
 * router (ASBR/advertising router). Seeds with directly adjacent neighbors as
 * first hops; traverses point-to-point router links (type 1). Transit/network
 * links are not modeled (no Network-LSA origination in this edge-only speaker),
 * so paths requiring them may remain unresolved. */
static bool spf_nexthop_to_router(uint32_t dest_rid, struct in_addr *out_nh)
{
    if (out_nh) out_nh->s_addr = 0;
    if (dest_rid == 0 || dest_rid == g_ospf.router_id)
        return false;

    /* direct adjacency first */
    struct in_addr direct = nbr_nexthop_for(dest_rid);
    if (direct.s_addr != 0 && nexthop_on_fabric(direct)) {
        if (out_nh) *out_nh = direct;
        return true;
    }

    spf_node_t nodes[OSPF_MAX_LSAS + OSPF_MAX_NEIGHBORS + 1];
    size_t nn = 0;

    #define SPF_ADD(r) ({ \
        int _idx = -1; \
        for (size_t _i = 0; _i < nn; _i++) if (nodes[_i].rid == (r)) { _idx = (int)_i; break; } \
        if (_idx < 0 && nn < sizeof(nodes)/sizeof(nodes[0])) { \
            memset(&nodes[nn], 0, sizeof(nodes[nn])); nodes[nn].rid = (r); nodes[nn].dist = UINT32_MAX; _idx = (int)nn++; \
        } _idx; })

    int self_idx = SPF_ADD(g_ospf.router_id);
    if (self_idx < 0) return false;
    nodes[self_idx].known = true;
    nodes[self_idx].dist = 0;

    /* seed direct neighbors */
    for (size_t i = 0; i < OSPF_MAX_NEIGHBORS; i++) {
        ospf_neighbor_t *nb = &g_ospf.nbrs[i];
        if (!nb->in_use || nb->state < NSTATE_2WAY)
            continue;
        int ni = SPF_ADD(nb->router_id);
        if (ni < 0) continue;
        if (!nexthop_on_fabric(nb->ip)) continue;
        if (1 < nodes[ni].dist) {
            nodes[ni].dist = 1;
            nodes[ni].nexthop = nb->ip;
            nodes[ni].known = true;
        }
    }

    /* add all router-LSA vertices */
    for (size_t i = 0; i < g_ospf.n_lsas; i++) {
        if (g_ospf.lsdb[i].valid && g_ospf.lsdb[i].hdr.type == OSPF_LSA_ROUTER)
            SPF_ADD(ntohl(g_ospf.lsdb[i].hdr.adv_router));
    }

    for (;;) {
        int u = -1;
        for (size_t i = 0; i < nn; i++) {
            if (!nodes[i].known || nodes[i].visited) continue;
            if (u < 0 || nodes[i].dist < nodes[u].dist) u = (int)i;
        }
        if (u < 0) break;
        nodes[u].visited = true;
        if (nodes[u].rid == dest_rid) break;

        const ospf_lsa_t *rlsa = find_router_lsa(nodes[u].rid);
        if (!rlsa || rlsa->body_len < 4) continue;
        uint16_t nlinks = 0;
        memcpy(&nlinks, rlsa->body + 2, 2);
        nlinks = ntohs(nlinks);
        size_t off = 4;
        for (uint16_t li = 0; li < nlinks && off + 12 <= rlsa->body_len; li++, off += 12) {
            uint8_t ltype = rlsa->body[off + 8];
            if (ltype != 1) continue; /* point-to-point */
            uint32_t nbr_rid = 0; memcpy(&nbr_rid, rlsa->body + off, 4); nbr_rid = ntohl(nbr_rid);
            uint16_t lm = 0; memcpy(&lm, rlsa->body + off + 10, 2);
            uint32_t cost = ntohs(lm);
            if (cost == 0) cost = 1;
            int vi = SPF_ADD(nbr_rid);
            if (vi < 0) continue;
            uint32_t nd = nodes[u].dist + cost;
            if (!nodes[vi].known || nd < nodes[vi].dist) {
                nodes[vi].dist = nd;
                nodes[vi].nexthop = nodes[u].nexthop; /* first-hop from root */
                nodes[vi].known = (nodes[u].nexthop.s_addr != 0);
            }
        }
    }

    for (size_t i = 0; i < nn; i++) {
        if (nodes[i].rid == dest_rid && nodes[i].known && nodes[i].nexthop.s_addr != 0 &&
            nexthop_on_fabric(nodes[i].nexthop)) {
            if (out_nh) *out_nh = nodes[i].nexthop;
            return true;
        }
    }
    #undef SPF_ADD
    return false;
}


static size_t ospf_default_candidates_locked(hadc_ctx_t *ctx, hadc_routing_default_candidate_t *out, size_t max)
{
    size_t n = 0;
    if (!g_ospf.enabled || !out || max == 0)
        return 0;
    for (size_t i = 0; i < g_ospf.n_lsas && n < max; i++) {
        ospf_lsa_t *e = &g_ospf.lsdb[i];
        if (!e->valid || e->self)
            continue;
        if (e->hdr.type != OSPF_LSA_AS_EXTERNAL)
            continue;
        if (ntohl(e->hdr.id) != 0)
            continue; /* only default route */
        if (e->body_len < 16)
            continue;
        /* body: mask(4), metric(4, includes E/TOS), fwd addr(4), tag(4) */
        uint32_t mask = 0, metric = 0, fwd = 0;
        memcpy(&mask, e->body, 4);
        memcpy(&metric, e->body + 4, 4);
        memcpy(&fwd, e->body + 8, 4);
        if (mask != 0)
            continue; /* not 0.0.0.0/0 */

        struct in_addr gw = {0};
        if (fwd != 0) {
            gw.s_addr = fwd;
        } else {
            /* forwarding addr 0.0.0.0 => traffic to ASBR; resolve via adjacent
             * neighbor or intra-area SPF path to advertising router. */
            gw = nbr_nexthop_for(ntohl(e->hdr.adv_router));
            if (gw.s_addr == 0)
                (void)spf_nexthop_to_router(ntohl(e->hdr.adv_router), &gw);
            if (gw.s_addr == 0 || !nexthop_on_fabric(gw))
                continue; /* nexthop unknown/unreachable on local fabric */
        }

        hadc_routing_default_candidate_t *c = &out[n++];
        memset(c, 0, sizeof(*c));
        c->gateway = gw;
        c->scope = HADC_ROUTE_SCOPE_REMOTE_MASTER;
        c->valid = true;
        char rid[INET_ADDRSTRLEN];
        u32_to_rid(ntohl(e->hdr.adv_router), rid, sizeof(rid));
        snprintf(c->origin, sizeof(c->origin), "%s", rid);
        c->age_s = lsa_effective_age(e);
        if (ctx) {
            for (size_t m = 0; m < ctx->conf.n_members; m++) {
                char ms[INET_ADDRSTRLEN] = "";
                inet_ntop(AF_INET, &ctx->conf.members[m].sync_address, ms, sizeof(ms));
                if (!strcmp(ms, rid)) {
                    snprintf(c->origin, sizeof(c->origin), "%s", ctx->conf.members[m].id);
                    break;
                }
            }
            /* remote cluster masters may be external OSPF peers; keep scope remote
             * here (local-master attribution is cluster/heartbeat-derived). */
        }
    }
    return n;
}

size_t hadc_ospf_default_candidates(hadc_ctx_t *ctx, hadc_routing_default_candidate_t *out, size_t max)
{
    OSPF_LOCK();
    size_t r = ospf_default_candidates_locked(ctx, out, max);
    OSPF_UNLOCK();
    return r;
}

static bool is_self_originated_prefix(struct in_addr pfx, struct in_addr mask)
{
    for (size_t i = 0; i < g_ospf.n_lsas; i++) {
        ospf_lsa_t *e = &g_ospf.lsdb[i];
        if (!e->valid || !e->self)
            continue;
        if (e->hdr.type == OSPF_LSA_ROUTER && e->body_len >= 4) {
            uint16_t nlinks = 0;
            memcpy(&nlinks, e->body + 2, 2);
            nlinks = ntohs(nlinks);
            size_t off = 4;
            for (uint16_t li = 0; li < nlinks && off + 12 <= e->body_len; li++, off += 12) {
                if (e->body[off + 8] != 3) continue;
                struct in_addr id, data;
                memcpy(&id, e->body + off, 4);
                memcpy(&data, e->body + off + 4, 4);
                if (id.s_addr == pfx.s_addr && data.s_addr == mask.s_addr)
                    return true;
            }
        } else if (e->hdr.type == OSPF_LSA_AS_EXTERNAL && e->body_len >= 8) {
            struct in_addr epfx, emask;
            epfx.s_addr = e->hdr.id;
            memcpy(&emask, e->body, 4);
            if (epfx.s_addr == pfx.s_addr && emask.s_addr == mask.s_addr)
                return true;
        }
    }
    return false;
}

static size_t ospf_learned_routes_locked(hadc_ctx_t *ctx, hadc_ospf_learned_route_t *out, size_t max)
{
    (void)ctx;
    size_t n = 0;
    if (!g_ospf.enabled || !out || max == 0)
        return 0;
    for (size_t i = 0; i < g_ospf.n_lsas && n < max; i++) {
        ospf_lsa_t *e = &g_ospf.lsdb[i];
        if (!e->valid || e->self)
            continue;

        struct in_addr pfx = {0}, mask = {0};
        struct in_addr nh = nbr_nexthop_for(ntohl(e->hdr.adv_router));
        if (nh.s_addr == 0)
            (void)spf_nexthop_to_router(ntohl(e->hdr.adv_router), &nh);
        uint32_t metric = 0;
        bool ok = false;

        if (e->hdr.type == OSPF_LSA_ROUTER && e->body_len >= 4) {
            uint16_t nlinks = 0;
            memcpy(&nlinks, e->body + 2, 2);
            nlinks = ntohs(nlinks);
            size_t off = 4;
            for (uint16_t li = 0; li < nlinks && off + 12 <= e->body_len && n < max; li++, off += 12) {
                if (e->body[off + 8] != 3)
                    continue;
                memcpy(&pfx, e->body + off, 4);
                memcpy(&mask, e->body + off + 4, 4);
                uint16_t m = 0; memcpy(&m, e->body + off + 10, 2); metric = ntohs(m);
                if (nh.s_addr == 0 || !nexthop_on_fabric(nh))
                    continue;
                if (is_self_originated_prefix(pfx, mask))
                    continue;
                hadc_ospf_learned_route_t *r = &out[n++];
                memset(r, 0, sizeof(*r));
                r->prefix = pfx; r->mask = mask; r->nexthop = nh; r->metric = metric;
                r->lsa_type = e->hdr.type; r->valid = true; r->age_s = lsa_effective_age(e);
                uint32_t mv = ntohl(mask.s_addr);
                unsigned plen = 0; for (int b = 31; b >= 0; b--) { if (mv & (1u << b)) plen++; else break; }
                r->prefixlen = plen;
                u32_to_rid(ntohl(e->hdr.adv_router), r->origin, sizeof(r->origin));
            }
            continue;
        } else if (e->hdr.type == OSPF_LSA_AS_EXTERNAL && e->body_len >= 16) {
            pfx.s_addr = e->hdr.id;
            memcpy(&mask, e->body, 4);
            memcpy(&metric, e->body + 4, 4);
            metric = ntohl(metric) & 0x00ffffffu;
            uint32_t fwd = 0; memcpy(&fwd, e->body + 8, 4);
            if (fwd != 0) {
                struct in_addr fwdnh; fwdnh.s_addr = fwd;
                if (nexthop_on_fabric(fwdnh)) nh = fwdnh;
                else { (void)spf_nexthop_to_router(ntohl(e->hdr.adv_router), &nh); }
            }
            /* skip default route here (handled as backup candidate/policy) */
            if (pfx.s_addr == 0 && mask.s_addr == 0)
                continue;
            ok = (nh.s_addr != 0 && nexthop_on_fabric(nh));
        } else if ((e->hdr.type == OSPF_LSA_SUMMARY || e->hdr.type == 4) && e->body_len >= 8) {
            pfx.s_addr = e->hdr.id;
            memcpy(&mask, e->body, 4);
            memcpy(&metric, e->body + 4, 4);
            metric = ntohl(metric) & 0x00ffffffu;
            ok = (nh.s_addr != 0 && nexthop_on_fabric(nh));
        }
        if (!ok)
            continue;
        if (is_self_originated_prefix(pfx, mask))
            continue;
        hadc_ospf_learned_route_t *r = &out[n++];
        memset(r, 0, sizeof(*r));
        r->prefix = pfx; r->mask = mask; r->nexthop = nh; r->metric = metric;
        r->lsa_type = e->hdr.type; r->valid = true; r->age_s = lsa_effective_age(e);
        uint32_t mv = ntohl(mask.s_addr);
        unsigned plen = 0; for (int b = 31; b >= 0; b--) { if (mv & (1u << b)) plen++; else break; }
        r->prefixlen = plen;
        u32_to_rid(ntohl(e->hdr.adv_router), r->origin, sizeof(r->origin));
    }

    /* The freshest LSA wins when several advertise the same prefix. */
    for (size_t i = 0; i < n; i++) {
        if (!out[i].valid)
            continue;
        for (size_t j = i + 1; j < n; j++) {
            if (!out[j].valid)
                continue;
            if (out[i].prefix.s_addr == out[j].prefix.s_addr &&
                out[i].mask.s_addr == out[j].mask.s_addr) {
                if (out[i].age_s <= out[j].age_s)
                    out[j].valid = false;
                else {
                    out[i].valid = false;
                    break;
                }
            }
        }
    }
    size_t kept = 0;
    for (size_t i = 0; i < n; i++)
        if (out[i].valid)
            out[kept++] = out[i];
    return kept;
}

size_t hadc_ospf_learned_routes(hadc_ctx_t *ctx, hadc_ospf_learned_route_t *out, size_t max)
{
    OSPF_LOCK();
    size_t r = ospf_learned_routes_locked(ctx, out, max);
    OSPF_UNLOCK();
    return r;
}


static void append_learned_prefix(json_t *arr, struct in_addr pfx, struct in_addr mask,
                                  const char *origin, const char *nexthop, const char *source, uint8_t lsa_type)
{
    char p[INET_ADDRSTRLEN], m[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pfx, p, sizeof(p));
    inet_ntop(AF_INET, &mask, m, sizeof(m));
    /* compute prefixlen */
    uint32_t mv = ntohl(mask.s_addr);
    int plen = 0;
    for (int i = 31; i >= 0; i--) { if (mv & (1u << i)) plen++; else break; }
    json_array_append_new(arr, json_pack("{s:s,s:i,s:s,s:s,s:s,s:s,s:i}",
                                         "prefix", p, "prefixlen", plen, "mask", m,
                                         "origin", origin, "nexthop", nexthop, "source", source,
                                         "lsa_type", (int)lsa_type));
}

static json_t *ospf_status_locked(hadc_ctx_t *ctx)
{
    (void)ctx;
    json_t *nbrs = json_array();
    int nfullish = 0;
    time_t now = time(NULL);
    for (size_t i = 0; i < OSPF_MAX_NEIGHBORS; i++) {
        ospf_neighbor_t *n = &g_ospf.nbrs[i];
        if (!n->in_use)
            continue;
        char rid[INET_ADDRSTRLEN], ip[INET_ADDRSTRLEN];
        u32_to_rid(n->router_id, rid, sizeof(rid));
        inet_ntop(AF_INET, &n->ip, ip, sizeof(ip));
        const char *sn = n->state == NSTATE_DOWN ? "down" :
                         n->state == NSTATE_INIT ? "init" :
                         n->state == NSTATE_2WAY ? "2way" :
                         n->state == NSTATE_EXSTART ? "exstart" :
                         n->state == NSTATE_EXCHANGE ? "exchange" :
                         n->state == NSTATE_LOADING ? "loading" : "full";
        if (n->state >= NSTATE_2WAY) nfullish++;
        json_array_append_new(nbrs, json_pack("{s:s,s:s,s:s,s:i}", "router_id", rid,
                                              "ip", ip, "state", sn,
                                              "dead_in", (int)(n->dead_at > now ? n->dead_at - now : 0)));
    }
    json_t *learned = json_array();
    int self_lsas = 0, other_lsas = 0;
    for (size_t i = 0; i < g_ospf.n_lsas; i++) {
        ospf_lsa_t *e = &g_ospf.lsdb[i];
        if (!e->valid) continue;
        if (e->self) { self_lsas++; continue; }
        other_lsas++;
        char origin[INET_ADDRSTRLEN];
        u32_to_rid(ntohl(e->hdr.adv_router), origin, sizeof(origin));
        struct in_addr nh = nbr_nexthop_for(ntohl(e->hdr.adv_router));
        if (nh.s_addr == 0)
            (void)spf_nexthop_to_router(ntohl(e->hdr.adv_router), &nh);
        char nhs[INET_ADDRSTRLEN] = "";
        if (nh.s_addr) inet_ntop(AF_INET, &nh, nhs, sizeof(nhs));

        if (e->hdr.type == OSPF_LSA_ROUTER && e->body_len >= 4) {
            /* parse stub links (type 3) */
            uint16_t nlinks = 0;
            memcpy(&nlinks, e->body + 2, 2);
            nlinks = ntohs(nlinks);
            size_t off = 4;
            for (uint16_t li = 0; li < nlinks && off + 12 <= e->body_len; li++, off += 12) {
                uint8_t ltype = e->body[off + 8];
                if (ltype != 3) continue; /* stub only */
                struct in_addr id, data;
                memcpy(&id, e->body + off, 4);
                memcpy(&data, e->body + off + 4, 4);
                /* id=network, data=mask for stub */
                append_learned_prefix(learned, id, data, origin, nhs, "router-stub", e->hdr.type);
            }
        } else if (e->hdr.type == OSPF_LSA_AS_EXTERNAL && e->body_len >= 8) {
            struct in_addr mask, pfx, fwd;
            pfx.s_addr = e->hdr.id;
            memcpy(&mask, e->body, 4);
            memcpy(&fwd, e->body + 8, 4);
            char enhs[INET_ADDRSTRLEN] = "";
            if (fwd.s_addr != 0) inet_ntop(AF_INET, &fwd, enhs, sizeof(enhs));
            else if (nh.s_addr) snprintf(enhs, sizeof(enhs), "%s", nhs);
            append_learned_prefix(learned, pfx, mask, origin, enhs, "as-external", e->hdr.type);
        } else if ((e->hdr.type == OSPF_LSA_SUMMARY || e->hdr.type == 4) && e->body_len >= 8) {
            struct in_addr mask, pfx;
            pfx.s_addr = e->hdr.id;
            memcpy(&mask, e->body, 4);
            append_learned_prefix(learned, pfx, mask, origin, nhs, "summary", e->hdr.type);
        }
    }
    return json_pack("{s:b,s:i,s:i,s:i,s:i,s:i,s:o,s:o}",
                     "enabled", g_ospf.enabled,
                     "neighbors", (int)json_array_size(nbrs),
                     "neighbors_2way", nfullish,
                     "lsdb_self", self_lsas,
                     "lsdb_other", other_lsas,
                     "lsdb_total", self_lsas + other_lsas,
                     "neighbor_list", nbrs,
                     "learned_prefixes", learned);
}

/* Last successful status snapshot so a busy OSPF thread never makes the ctl
 * path wait: when the lock is busy we serve the snapshot marked stale. */
static json_t *g_ospf_status_snapshot;
static pthread_mutex_t g_ospf_snap_lock = PTHREAD_MUTEX_INITIALIZER;

json_t *hadc_ospf_status(hadc_ctx_t *ctx)
{
    if (pthread_mutex_trylock(&g_ospf.lock) == 0) {
        json_t *r = ospf_status_locked(ctx);
        pthread_mutex_lock(&g_ospf_snap_lock);
        if (g_ospf_status_snapshot)
            json_decref(g_ospf_status_snapshot);
        g_ospf_status_snapshot = r ? json_incref(r) : NULL;
        pthread_mutex_unlock(&g_ospf_snap_lock);
        OSPF_UNLOCK();
        return r;
    }
    pthread_mutex_lock(&g_ospf_snap_lock);
    json_t *r = g_ospf_status_snapshot ? json_deep_copy(g_ospf_status_snapshot) : NULL;
    if (r)
        json_object_set_new(r, "stale", json_true());
    pthread_mutex_unlock(&g_ospf_snap_lock);
    return r;
}

/* OSPF thread: owns the raw socket fd and the protocol cadence (RX processing,
 * hello send, neighbor FSM/LSDB/SPF) so a stall is a real process-wide stop, not
 * main-loop contention. poll() wakes promptly on RX and on the shutdown pipe; the
 * 1 s timeout preserves the old tick cadence. RX/tick run under the g_ospf lock;
 * the lock is not held across poll(). */
static void *ospf_thread_main(void *arg)
{
    (void)arg;
    while (!g_ospf.stop) {
        struct pollfd pfd[2];
        nfds_t nfd = 0;
        pfd[nfd].fd = g_ospf.fd;
        pfd[nfd].events = POLLIN;
        pfd[nfd].revents = 0;
        nfd++;
        if (g_ospf.pipe[0] >= 0) {
            pfd[nfd].fd = g_ospf.pipe[0];
            pfd[nfd].events = POLLIN;
            pfd[nfd].revents = 0;
            nfd++;
        }
        int r = poll(pfd, nfd, OSPF_TICK_MS);
        if (g_ospf.stop)
            break;
        OSPF_LOCK();
        if (r > 0) {
            for (nfds_t i = 0; i < nfd; i++) {
                if (!(pfd[i].revents & POLLIN))
                    continue;
                if (pfd[i].fd == g_ospf.fd) {
                    ospf_drain_rx_locked();
                } else { /* wake-up pipe: drain it, no packets to process */
                    char b;
                    while (read(pfd[i].fd, &b, 1) == 1) {}
                }
            }
        }
        ospf_tick_locked();
        OSPF_UNLOCK();
    }
    return NULL;
}

int hadc_ospf_spawn(hadc_ctx_t *ctx)
{
    g_ospf.ctx = ctx;
    if (!g_ospf.enabled || g_ospf.fd < 0 || g_ospf.thread_started)
        return 0;
    if (pthread_create(&g_ospf.thread, NULL, ospf_thread_main, NULL) != 0) {
        hadc_warn("ospf: pthread_create failed (OSPF thread disabled)");
        return -1;
    }
    g_ospf.thread_started = true;
    return 0;
}

void hadc_ospf_lock(void)
{
    pthread_mutex_lock(&g_ospf.lock);
}

void hadc_ospf_unlock(void)
{
    pthread_mutex_unlock(&g_ospf.lock);
}

/* Persist hooks (called by persist.c from the main loop; arr is a json array). */
void hadc_ospf_collect_self_lsas(void *arr)
{
    json_t *a = (json_t *)arr;
    if (!a || !json_is_array(a))
        return;
    pthread_mutex_lock(&g_ospf.lock);
    for (size_t i = 0; i < g_ospf.n_lsas; i++) {
        if (!g_ospf.lsdb[i].valid || !g_ospf.lsdb[i].self)
            continue;
        char hx[2 * OSPF_MTU + 1];
        size_t n = g_ospf.lsdb[i].body_len;
        for (size_t k = 0; k < n; k++)
            sprintf(hx + 2 * k, "%02x", g_ospf.lsdb[i].body[k]);
        hx[2 * n] = '\0';
        json_array_append_new(a, json_pack("{s:i, s:i, s:i, s:i, s:s}", "type",
                                           (json_int_t)g_ospf.lsdb[i].hdr.type, "id",
                                           (json_int_t)ntohl(g_ospf.lsdb[i].hdr.id), "seq",
                                           (json_int_t)ntohl(g_ospf.lsdb[i].hdr.seq), "age",
                                           (json_int_t)ntohs(g_ospf.lsdb[i].hdr.age),
                                           "body_hex", json_string(hx)));
    }
    pthread_mutex_unlock(&g_ospf.lock);
}

uint64_t hadc_ospf_next_seq(void)
{
    uint32_t s;
    pthread_mutex_lock(&g_ospf.lock);
    s = g_ospf.lsa_seq;
    pthread_mutex_unlock(&g_ospf.lock);
    return (uint64_t)s;
}
