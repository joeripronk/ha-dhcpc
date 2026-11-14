/* Conntrack sync worker (HA-DHCPC-CONNTRACK.md).
 * v1: IPv4-only, separate thread, master-initiated TCP replication, binary
 * protocol, rtnetlink local/VIP address classification cache, SIP helper
 * status cache, staged apply on slaves. Conntrack kernel export/apply uses a
 * backend hook layer (nfnetlink/libnetfilter_conntrack integration point). */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <jansson.h>
#include <limits.h>
#include <stddef.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nfnetlink_cthelper.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/config.h"
#include "ha-dhcpc/conntrack.h"
#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/log.h"
#include "internal.h"

#define HADC_CT_MAGIC0 'H'
#define HADC_CT_MAGIC1 'C'
#define HADC_CT_MAGIC2 'T'
#define HADC_CT_MAGIC3 '1'
#define HADC_CT_VER 1
#define HADC_CT_MAX_FRAME 65536
#define HADC_CT_MAX_OWNED 128
#define HADC_CT_SHADOW_MAX 4096
#define HADC_CT_TXQ_MAX 1024
#define HADC_CT_BATCH_MAX 32
#define HADC_CT_APPLY_PENDING_MAX 128
#define HADC_CT_APPLY_MAX_RETRIES 3

enum {
    HADC_CT_MSG_HELLO = 1,
    HADC_CT_MSG_HELLO_ACK = 2,
    HADC_CT_MSG_SNAPSHOT_BEGIN = 3,
    HADC_CT_MSG_SNAPSHOT_ENTRY = 4,
    HADC_CT_MSG_SNAPSHOT_END = 5,
    HADC_CT_MSG_UPSERT = 6,
    HADC_CT_MSG_DELETE = 7,
    HADC_CT_MSG_RESYNC_REQ = 8,
    HADC_CT_MSG_KEEPALIVE = 9,
    HADC_CT_MSG_ERROR = 10,
};

enum {
    HADC_CT_F_RESYNC = 0x0001,
    HADC_CT_F_SNAPSHOT = 0x0002,
};

#pragma pack(push, 1)
typedef struct {
    uint8_t magic[4];
    uint8_t ver;
    uint8_t type;
    uint16_t flags;
    uint32_t len;
    uint32_t seq;
    uint32_t ack_seq;
} hadc_ct_hdr_t;

typedef struct {
    uint8_t family;   /* AF_INET */
    uint8_t addr_len; /* 4 */
    uint8_t proto;    /* IPPROTO_TCP/UDP/... */
    uint8_t tcp_state;
    uint32_t status;
    uint32_t timeout_s;
    uint32_t mark;
    uint32_t zone;
    uint32_t orig_src;
    uint32_t orig_dst;
    uint16_t orig_sport;
    uint16_t orig_dport;
    uint32_t repl_src;
    uint32_t repl_dst;
    uint16_t repl_sport;
    uint16_t repl_dport;
    uint8_t flags; /* 1=nated,2=related/helper,4=assured,8=delete */
    uint8_t helper_id; /* 0 none, 1 sip */
    uint16_t rsv;
} hadc_ct_entry_v1_t;
#pragma pack(pop)

typedef struct {
    uint8_t type; /* HADC_CT_MSG_* */
    uint16_t flags;
    uint32_t len;
    uint8_t data[sizeof(hadc_ct_entry_v1_t)];
} hadc_ct_txop_t;

typedef struct {
    bool in_use;
    char id[HADC_NODE_ID_MAX];
    struct in_addr addr;
    int fd;
    bool connected;
    bool hello_sent;
    bool hello_ok;
    bool accepted; /* slave accepted inbound from master */
    bool snapshot_active;
    bool peer_is_master;
    uint32_t tx_seq;
    uint32_t rx_seq;
    uint64_t last_connect_ms;
    uint64_t last_seen_ms;
    uint64_t last_send_ms;
    uint64_t drops;
    uint64_t resyncs;
    bool need_resync;
    hadc_ct_txop_t txq[HADC_CT_TXQ_MAX];
    size_t txq_head;
    size_t txq_tail;
    size_t txq_count;
    uint8_t tx_partial[HADC_CT_MAX_FRAME + sizeof(hadc_ct_hdr_t)];
    size_t tx_partial_len;
    size_t tx_partial_off;
    uint8_t tx_partial_type;
    bool tx_partial_counted;
    uint8_t rxbuf[HADC_CT_MAX_FRAME + sizeof(hadc_ct_hdr_t)];
    size_t rxlen;
} hadc_ct_peer_t;

typedef struct {
    hadc_ct_entry_v1_t e;
    uint64_t updated_ms;
    bool valid;
    bool seen_in_snapshot;
} hadc_ct_shadow_ent_t;

typedef struct {
    uint32_t seq;
    hadc_ct_entry_v1_t e;
    bool is_del;
    bool create;
    uint8_t retries;
    uint64_t next_retry_ms;
    bool in_use;
} hadc_ct_apply_pending_t;

struct hadc_conntrack {
    pthread_mutex_t lock;
    pthread_t thread;
    bool thread_started;
    bool stop;
    bool running;
    int wakefd;
    int listen_fd;
    int rtnl_fd; /* NETLINK_ROUTE addr monitor/dump for IPv4 local+VIP discovery */
    int ctnl_fd; /* NFNETLINK conntrack dump/events (raw, best-effort) */
    bool ctnl_dump_pending;
    uint64_t ctnl_dump_start_ms;
    uint32_t ctnl_dump_seq;
    uint32_t ctnl_apply_seq;
    hadc_ct_apply_pending_t apply_pending[HADC_CT_APPLY_PENDING_MAX];
    bool apply_shadow_pending;
    bool rx_snapshot_active;
    bool slave_resync_requested;
    hadc_ctx_t *ctx;

    /* config snapshot */
    bool enabled;
    uint16_t port;
    uint32_t max_queue_entries;
    bool snapshot_on_connect;
    uint32_t resync_interval_s;
    bool non_local_only;
    bool include_related;
    bool exclude_loopback;
    int sip_mode;
    uint32_t helper_cache_refresh_s;
    int slave_apply_mode;
    uint32_t max_entry_age_s;

    hadc_role_t role;
    char self[HADC_NODE_ID_MAX];
    char interface[HADC_IFNAME_MAX];
    struct in_addr self_sync;
    hadc_ct_peer_t peers[HADC_MEMBERS_MAX];
    size_t n_peers;

    /* owned/managed IPv4 set for classification (IPv4-only v1) */
    struct in_addr owned_addrs[HADC_CT_MAX_OWNED];
    size_t n_owned;
    bool addr_cache_valid;
    uint64_t last_addr_refresh_ms;

    hadc_ct_shadow_ent_t shadow[HADC_CT_SHADOW_MAX];
    size_t n_shadow;

    hadc_ct_status_t st;
    uint64_t last_helper_refresh_ms;
    uint64_t last_resync_ms;
    uint32_t generation;
};

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void ct_wake(struct hadc_conntrack *ct)
{
    if (!ct || ct->wakefd < 0)
        return;
    uint64_t one = 1;
    (void)!write(ct->wakefd, &one, sizeof(one));
}

static void drain_wake(int fd)
{
    uint64_t v;
    while (read(fd, &v, sizeof(v)) > 0)
        ;
}

static void close_peer(hadc_ct_peer_t *p)
{
    if (!p)
        return;
    if (p->fd >= 0)
        close(p->fd);
    p->fd = -1;
    p->connected = false;
    p->hello_sent = false;
    p->hello_ok = false;
    p->accepted = false;
    p->snapshot_active = false;
    p->rxlen = 0;
    p->txq_head = p->txq_tail = p->txq_count = 0;
    p->tx_partial_len = 0;
    p->tx_partial_off = 0;
    p->tx_partial_type = 0;
    p->tx_partial_counted = false;
}

static bool ip_in_owned(const struct hadc_conntrack *ct, uint32_t be_addr)
{
    for (size_t i = 0; i < ct->n_owned; i++) {
        if (ct->owned_addrs[i].s_addr == be_addr)
            return true;
    }
    return false;
}

static bool is_loopback_ipv4(uint32_t be_addr)
{
    uint32_t h = ntohl(be_addr);
    return (h & 0xff000000u) == 0x7f000000u;
}

static bool classify_non_local(struct hadc_conntrack *ct, const hadc_ct_entry_v1_t *e, const char **reason)
{
    if (e->family != AF_INET || e->addr_len != 4) {
        if (reason) *reason = "non_ipv4";
        return false;
    }
    if (ct->exclude_loopback &&
        (is_loopback_ipv4(e->orig_src) || is_loopback_ipv4(e->orig_dst) ||
         is_loopback_ipv4(e->repl_src) || is_loopback_ipv4(e->repl_dst))) {
        if (reason) *reason = "loopback";
        return false;
    }

    bool nated = (e->flags & 1) || e->orig_src != e->repl_dst || e->orig_dst != e->repl_src ||
                 e->orig_sport != e->repl_dport || e->orig_dport != e->repl_sport;
    bool related = (e->flags & 2) != 0;
    bool owned = ip_in_owned(ct, e->orig_src) || ip_in_owned(ct, e->orig_dst) ||
                 ip_in_owned(ct, e->repl_src) || ip_in_owned(ct, e->repl_dst);

    if (ct->include_related && related && (owned || nated)) {
        if (reason) *reason = "related_helper";
        return true;
    }
    if (ct->non_local_only) {
        if (nated && (owned || ip_in_owned(ct, e->orig_src) || ip_in_owned(ct, e->repl_dst))) {
            if (reason) *reason = "nat_managed";
            return true;
        }
        if (owned && nated) {
            if (reason) *reason = "owned_nat";
            return true;
        }
        if (reason) *reason = owned ? "owned_not_forwarded" : "not_managed";
        return false;
    }
    if (owned || nated) {
        if (reason) *reason = "managed";
        return true;
    }
    if (reason) *reason = "not_managed";
    return false;
}

static void add_owned_addr_locked(struct hadc_conntrack *ct, struct in_addr a)
{
    if (a.s_addr == 0 || ct->n_owned >= HADC_CT_MAX_OWNED)
        return;
    for (size_t i = 0; i < ct->n_owned; i++)
        if (ct->owned_addrs[i].s_addr == a.s_addr)
            return;
    ct->owned_addrs[ct->n_owned++] = a;
}

static bool is_managed_ifname(const struct hadc_conntrack *ct, hadc_ctx_t *ctx, const char *ifname)
{
    if (!ifname || !*ifname)
        return false;
    if (ctx && !strcmp(ifname, ctx->conf.interface))
        return true;
    if (ct && ct->interface[0] && !strcmp(ifname, ct->interface))
        return true;
    if (ctx) {
        for (size_t i = 0; i < ctx->conf.cluster.n_ifaces; i++)
            if (!strcmp(ifname, ctx->conf.cluster.ifaces[i].interface))
                return true;
    }
    return false;
}

static void rebuild_owned_base_locked(struct hadc_conntrack *ct, hadc_ctx_t *ctx)
{
    ct->n_owned = 0;
    /* VIP/cluster addresses and current lease/public address are always managed. */
    if (ctx) {
        for (size_t i = 0; i < ctx->conf.cluster.n_ifaces && ct->n_owned < HADC_CT_MAX_OWNED; i++) {
            const hadc_cluster_if_t *ci = &ctx->conf.cluster.ifaces[i];
            for (size_t j = 0; j < ci->n_addrs && ct->n_owned < HADC_CT_MAX_OWNED; j++)
                add_owned_addr_locked(ct, ci->addrs[j].address);
        }
        add_owned_addr_locked(ct, ctx->lease.address);
    }
}

static void refresh_owned_addrs_getifaddrs(struct hadc_conntrack *ct, hadc_ctx_t *ctx)
{
    rebuild_owned_base_locked(ct, ctx);
    struct ifaddrs *ifas = NULL;
    if (getifaddrs(&ifas) == 0) {
        for (struct ifaddrs *ifa = ifas; ifa && ct->n_owned < HADC_CT_MAX_OWNED; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
                continue;
            if (!is_managed_ifname(ct, ctx, ifa->ifa_name))
                continue;
            add_owned_addr_locked(ct, ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr);
        }
        freeifaddrs(ifas);
    }
    ct->addr_cache_valid = true;
    ct->last_addr_refresh_ms = now_ms();
}

static int rtnl_open(struct hadc_conntrack *ct)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0)
        return -1;
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK,
                              .nl_groups = RTMGRP_IPV4_IFADDR };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    ct->rtnl_fd = fd;
    return 0;
}

static int rtnl_dump_addrs(struct hadc_conntrack *ct)
{
    if (ct->rtnl_fd < 0)
        return -1;
    struct {
        struct nlmsghdr nh;
        struct ifaddrmsg ifa;
    } req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nh.nlmsg_type = RTM_GETADDR;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_seq = 1;
    req.ifa.ifa_family = AF_INET;
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    return sendto(ct->rtnl_fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0 ? -1 : 0;
}

static void handle_rtnl_addr_msg(struct hadc_conntrack *ct, hadc_ctx_t *ctx, struct nlmsghdr *nh)
{
    if (nh->nlmsg_type != RTM_NEWADDR && nh->nlmsg_type != RTM_DELADDR)
        return;
    struct ifaddrmsg *ifa = NLMSG_DATA(nh);
    if (ifa->ifa_family != AF_INET)
        return;
    char ifname[IF_NAMESIZE] = "";
    if (!if_indextoname(ifa->ifa_index, ifname))
        return;
    if (!is_managed_ifname(ct, ctx, ifname))
        return;

    int len = (int)(nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));
    struct rtattr *rta = IFA_RTA(ifa);
    for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type != IFA_LOCAL && rta->rta_type != IFA_ADDRESS)
            continue;
        if (RTA_PAYLOAD(rta) < sizeof(struct in_addr))
            continue;
        struct in_addr a;
        memcpy(&a, RTA_DATA(rta), sizeof(a));
        if (nh->nlmsg_type == RTM_NEWADDR)
            add_owned_addr_locked(ct, a);
        /* deletions handled by periodic full refresh/getifaddrs rebuild */
        ct->addr_cache_valid = true;
        ct->last_addr_refresh_ms = now_ms();
        break;
    }
}

static void drain_rtnl(struct hadc_conntrack *ct, hadc_ctx_t *ctx)
{
    if (ct->rtnl_fd < 0)
        return;
    uint8_t buf[8192];
    bool changed = false;
    for (;;) {
        ssize_t n = recv(ct->rtnl_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                break;
            close(ct->rtnl_fd);
            ct->rtnl_fd = -1;
            break;
        }
        if (n == 0)
            break;
        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (unsigned)n); nh = NLMSG_NEXT(nh, n)) {
            if (nh->nlmsg_type == NLMSG_DONE)
                break;
            if (nh->nlmsg_type == NLMSG_ERROR)
                continue;
            if (nh->nlmsg_type == RTM_NEWADDR || nh->nlmsg_type == RTM_DELADDR) {
                handle_rtnl_addr_msg(ct, ctx, nh);
                changed = true;
            }
        }
    }
    if (changed || !ct->addr_cache_valid)
        rtnl_dump_addrs(ct);
}

#define HADC_NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#define HADC_NLA_OK(nla, len) ((len) >= HADC_NLA_HDRLEN && \
    (nla)->nla_len >= sizeof(struct nlattr) && (nla)->nla_len <= (len))
#define HADC_NLA_DATA(nla) ((void *)((char *)(nla) + HADC_NLA_HDRLEN))
#define HADC_NLA_DATALEN(nla) ((int)(nla)->nla_len - HADC_NLA_HDRLEN)

static struct nlattr *nla_find(struct nlattr *head, int len, int type)
{
    for (struct nlattr *n = head; HADC_NLA_OK(n, len); ) {
        if (n->nla_type == type) return n;
        int _sz = NLA_ALIGN(n->nla_len);
        len -= _sz;
        n = (struct nlattr *)((char *)n + _sz);
    }
    return NULL;
}
static uint32_t nla_get_u32(struct nlattr *n){ uint32_t v=0; if(n&&HADC_NLA_DATALEN(n)>=4) memcpy(&v,HADC_NLA_DATA(n),4); return v; }
static uint16_t nla_get_u16(struct nlattr *n){ uint16_t v=0; if(n&&HADC_NLA_DATALEN(n)>=2) memcpy(&v,HADC_NLA_DATA(n),2); return v; }
static uint8_t  nla_get_u8 (struct nlattr *n){ uint8_t v=0; if(n&&HADC_NLA_DATALEN(n)>=1) memcpy(&v,HADC_NLA_DATA(n),1); return v; }

static int queue_entry(struct hadc_conntrack *ct, hadc_ct_peer_t *p, uint8_t type, const hadc_ct_entry_v1_t *e);
static void stage_or_apply(struct hadc_conntrack *ct, const hadc_ct_entry_v1_t *e, bool del);

static void ctnl_close(struct hadc_conntrack *ct){
    if(ct->ctnl_fd>=0) close(ct->ctnl_fd);
    ct->ctnl_fd=-1;
    if (ct->ctnl_dump_pending) {
        for (size_t i = 0; i < ct->n_peers; i++) {
            if (ct->peers[i].snapshot_active) {
                ct->peers[i].snapshot_active = false;
                ct->peers[i].need_resync = true;
                ct->st.resync_count++;
            }
        }
    }
    ct->ctnl_dump_pending=false;
    ct->ctnl_dump_start_ms = 0;
    memset(ct->apply_pending, 0, sizeof(ct->apply_pending));
}
static int ctnl_open(struct hadc_conntrack *ct){
    if(ct->ctnl_fd>=0) return 0;
    int fd=socket(AF_NETLINK,SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC,NETLINK_NETFILTER);
    if(fd<0) return -1;
    struct sockaddr_nl sa={.nl_family=AF_NETLINK,.nl_groups=(1u<<(NFNLGRP_CONNTRACK_NEW-1))|(1u<<(NFNLGRP_CONNTRACK_UPDATE-1))|(1u<<(NFNLGRP_CONNTRACK_DESTROY-1))};
    if(bind(fd,(struct sockaddr*)&sa,sizeof(sa))!=0){close(fd);return -1;}
    ct->ctnl_fd=fd;
    ct->ctnl_apply_seq = 1;
    memset(ct->apply_pending, 0, sizeof(ct->apply_pending));
    return 0;
}
static int ctnl_request_dump(struct hadc_conntrack *ct){
    if(ct->ctnl_fd<0) return -1;
    struct {struct nlmsghdr nh; struct nfgenmsg nf;} req; memset(&req,0,sizeof(req));
    req.nh.nlmsg_len=NLMSG_LENGTH(sizeof(req.nf));
    req.nh.nlmsg_type=(NFNL_SUBSYS_CTNETLINK<<8)|IPCTNL_MSG_CT_GET;
    req.nh.nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP; req.nh.nlmsg_seq=++ct->ctnl_dump_seq;
    req.nf.nfgen_family=AF_INET; req.nf.version=NFNETLINK_V0;
    if(send(ct->ctnl_fd,&req,req.nh.nlmsg_len,0)<0) {
        ctnl_close(ct);
        return -1;
    }
    ct->ctnl_dump_pending=true;
    ct->ctnl_dump_start_ms = now_ms();
    return 0;
}

static int parse_tuple_v4(struct nlattr *tuple,uint32_t *sip,uint16_t *sp,uint8_t *proto,uint32_t *dip,uint16_t *dp){
    if(!tuple) return -1;
    uint8_t prnum = proto ? *proto : 0;
    struct nlattr *ta=(struct nlattr*)HADC_NLA_DATA(tuple); int tl=HADC_NLA_DATALEN(tuple);
    struct nlattr *ipn=nla_find(ta,tl,CTA_TUPLE_IP), *prn=nla_find(ta,tl,CTA_TUPLE_PROTO);
    if(ipn){ struct nlattr *ia=(struct nlattr*)HADC_NLA_DATA(ipn); int il=HADC_NLA_DATALEN(ipn);
        struct nlattr *v4s=nla_find(ia,il,CTA_IP_V4_SRC), *v4d=nla_find(ia,il,CTA_IP_V4_DST);
        if(v4s&&HADC_NLA_DATALEN(v4s)>=4&&sip) memcpy(sip,HADC_NLA_DATA(v4s),4);
        if(v4d&&HADC_NLA_DATALEN(v4d)>=4&&dip) memcpy(dip,HADC_NLA_DATA(v4d),4);
    }
    if(prn){ struct nlattr *pa=(struct nlattr*)HADC_NLA_DATA(prn); int pl=HADC_NLA_DATALEN(prn);
        struct nlattr *num=nla_find(pa,pl,CTA_PROTO_NUM);
        if(num){ prnum = nla_get_u8(num); if(proto) *proto = prnum; }
        if(prnum==IPPROTO_ICMP){
            struct nlattr *id=nla_find(pa,pl,CTA_PROTO_ICMP_ID), *ty=nla_find(pa,pl,CTA_PROTO_ICMP_TYPE), *co=nla_find(pa,pl,CTA_PROTO_ICMP_CODE);
            if(id&&sp) *sp=nla_get_u16(id);
            if(dp){ uint8_t t=ty?nla_get_u8(ty):0, c=co?nla_get_u8(co):0; *dp = htons((uint16_t)((t<<8)|c)); }
        } else {
            struct nlattr *spr=nla_find(pa,pl,CTA_PROTO_SRC_PORT), *dpr=nla_find(pa,pl,CTA_PROTO_DST_PORT);
            if(spr&&sp) *sp=nla_get_u16(spr);
            if(dpr&&dp) *dp=nla_get_u16(dpr);
        }
    }
    return 0;
}

static bool parse_ct_entry_v4(const struct nlmsghdr *nh, hadc_ct_entry_v1_t *out, bool *is_del){
    memset(out,0,sizeof(*out)); out->family=AF_INET; out->addr_len=4; if(is_del)*is_del=false;
    if((int)nh->nlmsg_len < (int)NLMSG_LENGTH(sizeof(struct nfgenmsg))) return false;
    struct nfgenmsg *nf=NLMSG_DATA(nh); if(nf->nfgen_family!=AF_INET) return false;
    uint16_t mtype=nh->nlmsg_type & 0x00ff; if(is_del)*is_del=(mtype==IPCTNL_MSG_CT_DELETE);
    struct nlattr *attr=(struct nlattr*)((char*)nf+NLMSG_ALIGN(sizeof(*nf)));
    int alen=(int)nh->nlmsg_len-(int)NLMSG_SPACE(sizeof(*nf));
    struct nlattr *orig=nla_find(attr,alen,CTA_TUPLE_ORIG), *repl=nla_find(attr,alen,CTA_TUPLE_REPLY);
    if(!orig||!repl) return false;
    uint8_t proto=0;
    (void)parse_tuple_v4(orig,&out->orig_src,&out->orig_sport,&proto,&out->orig_dst,&out->orig_dport);
    out->proto = proto;
    (void)parse_tuple_v4(repl,&out->repl_src,&out->repl_sport,&proto,&out->repl_dst,&out->repl_dport);
    struct nlattr *st=nla_find(attr,alen,CTA_STATUS), *to=nla_find(attr,alen,CTA_TIMEOUT), *mk=nla_find(attr,alen,CTA_MARK), *zn=nla_find(attr,alen,CTA_ZONE), *pi=nla_find(attr,alen,CTA_PROTOINFO), *hp=nla_find(attr,alen,CTA_HELP);
    if(st) out->status=ntohl(nla_get_u32(st));
    if(to) out->timeout_s=ntohl(nla_get_u32(to));
    if(mk) out->mark=ntohl(nla_get_u32(mk));
    if(zn) out->zone=ntohl(nla_get_u32(zn));
    if(pi){ struct nlattr *pia=(struct nlattr*)HADC_NLA_DATA(pi); int pil=HADC_NLA_DATALEN(pi);
        struct nlattr *tcp=nla_find(pia,pil,CTA_PROTOINFO_TCP);
        if(tcp){ struct nlattr *ta=(struct nlattr*)HADC_NLA_DATA(tcp); int tl=HADC_NLA_DATALEN(tcp);
            struct nlattr *state=nla_find(ta,tl,CTA_PROTOINFO_TCP_STATE); if(state) out->tcp_state=nla_get_u8(state); }
    }
    if(out->status & IPS_NAT_MASK) out->flags|=1;
    if(out->status & IPS_ASSURED) out->flags|=4;
    if(hp){ struct nlattr *ha=(struct nlattr*)HADC_NLA_DATA(hp); int hl=HADC_NLA_DATALEN(hp);
        struct nlattr *name=nla_find(ha,hl,CTA_HELP_NAME);
        if(name){ int dl=HADC_NLA_DATALEN(name); if(dl>0){ char nb[32]; int c=dl<31?dl:31; memcpy(nb,HADC_NLA_DATA(name),c); nb[c]='\0'; if(strstr(nb,"sip")){ out->helper_id=1; out->flags|=2; } } }
    }
    return true;
}

static void master_queue_entry_all(struct hadc_conntrack *ct, uint8_t type, const hadc_ct_entry_v1_t *e, const hadc_ct_peer_t *exclude)
{
    for (size_t i = 0; i < ct->n_peers; i++) {
        hadc_ct_peer_t *p = &ct->peers[i];
        if (!p->connected || !p->hello_ok) continue;
        if (exclude && p == exclude) continue;
        if (type == HADC_CT_MSG_SNAPSHOT_ENTRY) {
            if (!p->snapshot_active) continue;
        } else {
            if (p->need_resync) continue;
        }
        if (queue_entry(ct, p, type, e) < 0) continue;
        uint32_t cap = ct->max_queue_entries ? ct->max_queue_entries : HADC_CT_TXQ_MAX;
        if (cap > HADC_CT_TXQ_MAX) cap = HADC_CT_TXQ_MAX;
        if (p->txq_count >= cap) p->need_resync = true;
    }
}

static bool nla_put(char *buf, size_t buflen, size_t *off, uint16_t type, const void *data, size_t dlen)
{
    size_t len = NLA_HDRLEN + dlen;
    size_t alen = NLA_ALIGN(len);
    if (*off + alen > buflen) return false;
    struct nlattr *nla = (struct nlattr *)(buf + *off);
    nla->nla_len = (uint16_t)len;
    nla->nla_type = type;
    if (dlen && data) memcpy((char *)nla + NLA_HDRLEN, data, dlen);
    memset((char *)nla + len, 0, alen - len);
    *off += alen;
    return true;
}
static bool nla_put_u32(char *buf, size_t buflen, size_t *off, uint16_t type, uint32_t v){ return nla_put(buf,buflen,off,type,&v,sizeof(v)); }
static bool nla_put_u16(char *buf, size_t buflen, size_t *off, uint16_t type, uint16_t v){ return nla_put(buf,buflen,off,type,&v,sizeof(v)); }
static bool nla_put_u8(char *buf, size_t buflen, size_t *off, uint16_t type, uint8_t v){ return nla_put(buf,buflen,off,type,&v,sizeof(v)); }
static size_t nla_nest_start(char *buf, size_t buflen, size_t *off, uint16_t type){
    size_t start = *off;
    if (!nla_put(buf, buflen, off, type, NULL, 0)) return (size_t)-1;
    return start;
}
static void nla_nest_end(char *buf, size_t start, size_t off){
    struct nlattr *nla = (struct nlattr *)(buf + start);
    nla->nla_len = (uint16_t)(off - start);
}

static bool build_tuple_nla(char *buf, size_t buflen, size_t *off, uint16_t type,
                            uint32_t src, uint32_t dst, uint8_t proto, uint16_t sport, uint16_t dport)
{
    size_t t = nla_nest_start(buf, buflen, off, type);
    if (t == (size_t)-1) return false;
    size_t ip = nla_nest_start(buf, buflen, off, CTA_TUPLE_IP);
    if (ip == (size_t)-1) return false;
    if (!nla_put(buf, buflen, off, CTA_IP_V4_SRC, &src, 4)) return false;
    if (!nla_put(buf, buflen, off, CTA_IP_V4_DST, &dst, 4)) return false;
    nla_nest_end(buf, ip, *off);

    size_t pr = nla_nest_start(buf, buflen, off, CTA_TUPLE_PROTO);
    if (pr == (size_t)-1) return false;
    if (!nla_put_u8(buf, buflen, off, CTA_PROTO_NUM, proto)) return false;
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_SCTP || proto == IPPROTO_UDPLITE || proto == IPPROTO_DCCP) {
        if (!nla_put_u16(buf, buflen, off, CTA_PROTO_SRC_PORT, sport)) return false;
        if (!nla_put_u16(buf, buflen, off, CTA_PROTO_DST_PORT, dport)) return false;
    } else if (proto == IPPROTO_ICMP) {
        if (!nla_put_u16(buf, buflen, off, CTA_PROTO_ICMP_ID, sport)) return false;
        if (!nla_put_u8(buf, buflen, off, CTA_PROTO_ICMP_TYPE, (uint8_t)(ntohs(dport) >> 8))) return false;
        if (!nla_put_u8(buf, buflen, off, CTA_PROTO_ICMP_CODE, (uint8_t)(ntohs(dport) & 0xff))) return false;
    }
    nla_nest_end(buf, pr, *off);
    nla_nest_end(buf, t, *off);
    return true;
}

static size_t ctnl_build_apply_msg(char *buf, size_t buflen, const hadc_ct_entry_v1_t *e, bool is_del, bool create, uint32_t seq)
{
    memset(buf, 0, buflen);
    struct nlmsghdr *nh = (struct nlmsghdr *)buf;
    struct nfgenmsg *nf = (struct nfgenmsg *)(buf + NLMSG_ALIGN(sizeof(*nh)));
    nh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | (is_del ? IPCTNL_MSG_CT_DELETE : IPCTNL_MSG_CT_NEW);
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | ((!is_del && create) ? NLM_F_CREATE : 0);
    nh->nlmsg_seq = seq;
    nf->nfgen_family = AF_INET;
    nf->version = NFNETLINK_V0;
    size_t off = NLMSG_ALIGN(sizeof(*nh)) + NLMSG_ALIGN(sizeof(*nf));

    if (!build_tuple_nla(buf, buflen, &off, CTA_TUPLE_ORIG,
                         e->orig_src, e->orig_dst, e->proto, e->orig_sport, e->orig_dport)) return 0;
    if (!build_tuple_nla(buf, buflen, &off, CTA_TUPLE_REPLY,
                         e->repl_src, e->repl_dst, e->proto, e->repl_sport, e->repl_dport)) return 0;

    if (!is_del) {
        uint32_t timeout = htonl(e->timeout_s ? e->timeout_s : 120);
        uint32_t status = htonl(e->status ? e->status : (IPS_CONFIRMED | IPS_SEEN_REPLY));
        (void)nla_put_u32(buf, buflen, &off, CTA_TIMEOUT, timeout);
        (void)nla_put_u32(buf, buflen, &off, CTA_STATUS, status);
        if (e->mark) (void)nla_put_u32(buf, buflen, &off, CTA_MARK, htonl(e->mark));
        if (e->zone) (void)nla_put_u16(buf, buflen, &off, CTA_ZONE, htons((uint16_t)e->zone));
        if (e->proto == IPPROTO_TCP && e->tcp_state) {
            size_t pi = nla_nest_start(buf, buflen, &off, CTA_PROTOINFO);
            if (pi != (size_t)-1) {
                size_t ti = nla_nest_start(buf, buflen, &off, CTA_PROTOINFO_TCP);
                if (ti != (size_t)-1) {
                    (void)nla_put_u8(buf, buflen, &off, CTA_PROTOINFO_TCP_STATE, e->tcp_state);
                    nla_nest_end(buf, ti, off);
                }
                nla_nest_end(buf, pi, off);
            }
        }
        if (e->helper_id == 1 || (e->flags & 2)) {
            size_t hn = nla_nest_start(buf, buflen, &off, CTA_HELP);
            if (hn != (size_t)-1) {
                (void)nla_put(buf, buflen, &off, CTA_HELP_NAME, "sip", 4);
                nla_nest_end(buf, hn, off);
            }
        }
    }

    nh->nlmsg_len = (uint32_t)off;
    return off;
}

static int ctnl_send_apply(struct hadc_conntrack *ct, hadc_ct_apply_pending_t *ap)
{
    if (!ct || ct->ctnl_fd < 0 || !ap || !ap->in_use) return -1;
    char buf[1024];
    size_t off = ctnl_build_apply_msg(buf, sizeof(buf), &ap->e, ap->is_del, ap->create, ap->seq);
    if (off == 0) return -1;
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    return sendto(ct->ctnl_fd, buf, off, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0 ? -1 : 0;
}

static hadc_ct_apply_pending_t *ctnl_alloc_apply(struct hadc_conntrack *ct)
{
    for (size_t i = 0; i < HADC_CT_APPLY_PENDING_MAX; i++)
        if (!ct->apply_pending[i].in_use) return &ct->apply_pending[i];
    return NULL;
}

static hadc_ct_apply_pending_t *ctnl_find_apply(struct hadc_conntrack *ct, uint32_t seq)
{
    if (seq == 0) return NULL;
    for (size_t i = 0; i < HADC_CT_APPLY_PENDING_MAX; i++)
        if (ct->apply_pending[i].in_use && ct->apply_pending[i].seq == seq)
            return &ct->apply_pending[i];
    return NULL;
}

static int ctnl_apply_entry(struct hadc_conntrack *ct, const hadc_ct_entry_v1_t *e, bool is_del)
{
    if (!ct || ct->ctnl_fd < 0 || !e) return -1;
    hadc_ct_apply_pending_t *ap = ctnl_alloc_apply(ct);
    if (!ap) {
        /* pending table full: best-effort untracked send */
        char buf[1024];
        uint32_t seq = ++ct->ctnl_apply_seq;
        size_t off = ctnl_build_apply_msg(buf, sizeof(buf), e, is_del, !is_del, seq);
        if (!off) return -1;
        struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
        return sendto(ct->ctnl_fd, buf, off, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0 ? -1 : 0;
    }
    memset(ap, 0, sizeof(*ap));
    ap->in_use = true;
    ap->seq = ++ct->ctnl_apply_seq;
    ap->e = *e;
    ap->is_del = is_del;
    ap->create = !is_del; /* try create; on EEXIST resolve by replacing without CREATE */
    ap->retries = 0;
    ap->next_retry_ms = 0;
    if (ctnl_send_apply(ct, ap) < 0) {
        ap->in_use = false;
        return -1;
    }
    return 0;
}

static void ctnl_apply_retry_tick(struct hadc_conntrack *ct, uint64_t now)
{
    if (!ct || ct->ctnl_fd < 0) return;
    for (size_t i = 0; i < HADC_CT_APPLY_PENDING_MAX; i++) {
        hadc_ct_apply_pending_t *ap = &ct->apply_pending[i];
        if (!ap->in_use) continue;
        if (ap->next_retry_ms == 0 || now < ap->next_retry_ms) continue;
        ap->next_retry_ms = 0;
        if (ctnl_send_apply(ct, ap) < 0) {
            ap->in_use = false;
            ct->st.dropped_entries++;
        }
    }
}

static void apply_shadow_all(struct hadc_conntrack *ct)
{
    if (!ct) return;
    if (ct->ctnl_fd < 0) (void)ctnl_open(ct);
    if (ct->ctnl_fd < 0) return;
    uint64_t now = now_ms();
    for (size_t i = 0; i < ct->n_shadow; i++) {
        hadc_ct_shadow_ent_t *s = &ct->shadow[i];
        if (!s->valid) continue;
        if (ct->max_entry_age_s > 0 && now - s->updated_ms > (uint64_t)ct->max_entry_age_s * 1000) {
            s->valid = false;
            continue;
        }
        (void)ctnl_apply_entry(ct, &s->e, false);
    }
}

static void prune_shadow(struct hadc_conntrack *ct, uint64_t now)
{
    if (!ct) return;
    if (ct->max_entry_age_s > 0) {
        uint64_t max_age = (uint64_t)ct->max_entry_age_s * 1000;
        for (size_t i = 0; i < ct->n_shadow; i++) {
            hadc_ct_shadow_ent_t *s = &ct->shadow[i];
            if (s->valid && now - s->updated_ms > max_age)
                s->valid = false;
        }
    }
    /* compact invalid head/tail slots so n_shadow does not grow unbounded */
    while (ct->n_shadow > 0 && !ct->shadow[ct->n_shadow - 1].valid)
        ct->n_shadow--;
}

static void drain_ctnl(struct hadc_conntrack *ct){
    if(ct->ctnl_fd<0) return;
    char buf[16384];
    bool in_dump = ct->ctnl_dump_pending;
    for(;;){
        ssize_t n=recv(ct->ctnl_fd,buf,sizeof(buf),MSG_DONTWAIT);
        if(n<0){ if(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR) break; ctnl_close(ct); return; }
        if(n==0) break;
        for(struct nlmsghdr *nh=(struct nlmsghdr*)buf; NLMSG_OK(nh,(unsigned)n); nh=NLMSG_NEXT(nh,n)){
            if(nh->nlmsg_type==NLMSG_DONE){ ct->ctnl_dump_pending=false; in_dump=false; continue; }
            if(nh->nlmsg_type==NLMSG_ERROR){
                const struct nlmsgerr *err = (const struct nlmsgerr *)NLMSG_DATA(nh);
                int e = err ? -err->error : 0;
                uint32_t eseq = err ? err->msg.nlmsg_seq : 0;
                hadc_ct_apply_pending_t *ap = ctnl_find_apply(ct, eseq);
                if (ap) {
                    if (e == 0) {
                        ap->in_use = false;
                    } else if (ap->is_del && e == ENOENT) {
                        ap->in_use = false; /* already gone */
                    } else if (!ap->is_del && e == EEXIST && ap->create) {
                        /* conflict: exists, retry as replace/update without CREATE */
                        ap->create = false;
                        ap->retries++;
                        ap->next_retry_ms = 0;
                        if (ctnl_send_apply(ct, ap) < 0) { ap->in_use = false; ct->st.dropped_entries++; }
                    } else if (!ap->is_del && e == ENOENT && ap->retries < HADC_CT_APPLY_MAX_RETRIES) {
                        /* missing during replace attempt, retry as create */
                        ap->create = true;
                        ap->retries++;
                        ap->next_retry_ms = now_ms() + 100;
                    } else if ((e == EBUSY || e == EAGAIN) && ap->retries < HADC_CT_APPLY_MAX_RETRIES) {
                        ap->retries++;
                        ap->next_retry_ms = now_ms() + 200;
                    } else {
                        ap->in_use = false;
                        if (e != EEXIST && e != ENOENT && e != EBUSY)
                            ct->st.dropped_entries++;
                    }
                } else {
                    if (e != 0) {
                        /* benign races for best-effort sync (already exists/gone) */
                        if (e != EEXIST && e != ENOENT && e != EBUSY)
                            ct->st.dropped_entries++;
                    }
                }
                if (in_dump) { ct->ctnl_dump_pending=false; in_dump=false; }
                continue;
            }
            if(NFNL_SUBSYS_ID(nh->nlmsg_type)!=NFNL_SUBSYS_CTNETLINK) continue;
            hadc_ct_entry_v1_t e; bool del=false;
            if(!parse_ct_entry_v4(nh,&e,&del)) continue;
            const char *reason=NULL;
            if(ct->non_local_only && !classify_non_local(ct,&e,&reason)) continue;
            if(!ct->include_related && (e.flags&2)) continue;
            if(ct->role==HADC_ROLE_MASTER){
                uint8_t mtype = in_dump ? HADC_CT_MSG_SNAPSHOT_ENTRY : HADC_CT_MSG_UPSERT;
                if(del){ mtype=HADC_CT_MSG_DELETE; e.flags|=8; }
                master_queue_entry_all(ct, mtype, &e, NULL);
            }
            /* slaves receive authoritative state over TCP; ignore local ctnl events */
        }
    }
}

static void refresh_owned_addrs_locked(struct hadc_conntrack *ct, hadc_ctx_t *ctx)
{
    /* Rebuild base (VIP/lease) + getifaddrs view, and request rtnetlink dump to
     * keep event-driven cache fresh for managed interfaces. */
    refresh_owned_addrs_getifaddrs(ct, ctx);
    if (ct->rtnl_fd >= 0)
        rtnl_dump_addrs(ct);
}

static bool probe_cthelper_sip(void)
{
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0)
        return false;
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return false;
    }

    struct {
        struct nlmsghdr nh;
        struct nfgenmsg nf;
    } req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.nf));
    req.nh.nlmsg_type = (NFNL_SUBSYS_CTHELPER << 8) | NFNL_MSG_CTHELPER_GET;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_seq = 1;
    req.nf.nfgen_family = AF_UNSPEC;
    req.nf.version = NFNETLINK_V0;
    if (send(fd, &req, req.nh.nlmsg_len, 0) < 0) {
        close(fd);
        return false;
    }

    bool found = false;
    uint64_t deadline = now_ms() + 150;
    while (now_ms() < deadline && !found) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 50);
        if (pr <= 0) continue;
        char buf[4096];
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n <= 0) break;
        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (unsigned)n); nh = NLMSG_NEXT(nh, n)) {
            if (nh->nlmsg_type == NLMSG_DONE) { close(fd); return found; }
            if (nh->nlmsg_type == NLMSG_ERROR) continue;
            if (NFNL_SUBSYS_ID(nh->nlmsg_type) != NFNL_SUBSYS_CTHELPER) continue;
            struct nfgenmsg *nfmsg = NLMSG_DATA(nh);
            struct nlattr *attr = (struct nlattr *)((char *)nfmsg + NLMSG_ALIGN(sizeof(*nfmsg)));
            int alen = (int)nh->nlmsg_len - (int)NLMSG_SPACE(sizeof(*nfmsg));
            for (struct nlattr *a = attr; HADC_NLA_OK(a, alen); ) {
                if (a->nla_type == NFCTH_NAME) {
                    int dl = HADC_NLA_DATALEN(a);
                    if (dl > 0) {
                        char name[32];
                        int c = dl < (int)sizeof(name) - 1 ? dl : (int)sizeof(name) - 1;
                        memcpy(name, HADC_NLA_DATA(a), c);
                        name[c] = '\0';
                        if (strstr(name, "sip"))
                            found = true;
                    }
                }
                int _sz = NLA_ALIGN(a->nla_len);
                alen -= _sz;
                a = (struct nlattr *)((char *)a + _sz);
            }
        }
    }
    close(fd);
    return found;
}

static void refresh_helper_cache_locked(struct hadc_conntrack *ct, bool nl_helper)
{
    /* SIP/VoIP helper status cache; nfnetlink probe result supplied by caller
     * (probe can block briefly and must not run under ct->lock). */
    ct->last_helper_refresh_ms = now_ms();
    if (ct->sip_mode == HADC_CT_SIP_OFF) {
        ct->st.sip_helper = HADC_CT_HELPER_UNAVAILABLE;
        snprintf(ct->st.sip_helper_reason, sizeof(ct->st.sip_helper_reason), "disabled");
        return;
    }

    bool sip_helper_on = false;
    bool helper_mod = false;

    FILE *f = fopen("/proc/sys/net/netfilter/nf_conntrack_helper", "r");
    if (f) {
        int v = 0;
        if (fscanf(f, "%d", &v) == 1)
            sip_helper_on = (v != 0);
        fclose(f);
    }
    f = fopen("/proc/modules", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "nf_conntrack_sip", 16) == 0 ||
                strncmp(line, "nf_nat_sip", 10) == 0) {
                helper_mod = true;
                break;
            }
        }
        fclose(f);
    }

    if (nl_helper || helper_mod || sip_helper_on) {
        ct->st.sip_helper = HADC_CT_HELPER_AVAILABLE;
        snprintf(ct->st.sip_helper_reason, sizeof(ct->st.sip_helper_reason),
                 "sip helper (nl=%d mod=%d sys=%d)",
                 nl_helper ? 1 : 0, helper_mod ? 1 : 0, sip_helper_on ? 1 : 0);
    } else if (access("/proc/net/nf_conntrack", R_OK) == 0) {
        ct->st.sip_helper = ct->sip_mode == HADC_CT_SIP_REQUIRE ? HADC_CT_HELPER_DEGRADED : HADC_CT_HELPER_UNKNOWN;
        snprintf(ct->st.sip_helper_reason, sizeof(ct->st.sip_helper_reason),
                 "conntrack available, sip helper not detected");
    } else {
        ct->st.sip_helper = ct->sip_mode == HADC_CT_SIP_REQUIRE ? HADC_CT_HELPER_DEGRADED : HADC_CT_HELPER_UNKNOWN;
        snprintf(ct->st.sip_helper_reason, sizeof(ct->st.sip_helper_reason),
                 "helper status unavailable (nfnetlink/proc probe)");
    }
}

static void snapshot_config_locked(struct hadc_conntrack *ct, hadc_ctx_t *ctx)
{
    ct->enabled = ctx->conf.conntrack_sync.enabled;
    ct->port = ctx->conf.conntrack_sync.port;
    ct->max_queue_entries = ctx->conf.conntrack_sync.max_queue_entries;
    ct->snapshot_on_connect = ctx->conf.conntrack_sync.snapshot_on_connect;
    ct->resync_interval_s = ctx->conf.conntrack_sync.resync_interval_s;
    ct->non_local_only = ctx->conf.conntrack_sync.filter.non_local_only;
    ct->include_related = ctx->conf.conntrack_sync.filter.include_related;
    ct->exclude_loopback = ctx->conf.conntrack_sync.filter.exclude_loopback;
    ct->sip_mode = (int)ctx->conf.conntrack_sync.helpers.sip;
    ct->helper_cache_refresh_s = ctx->conf.conntrack_sync.helpers.cache_refresh_s;
    ct->slave_apply_mode = (int)ctx->conf.conntrack_sync.apply.slave_apply;
    ct->max_entry_age_s = ctx->conf.conntrack_sync.apply.max_entry_age_s;
    ct->role = ctx->role;
    snprintf(ct->self, sizeof(ct->self), "%s", ctx->conf.self);
    snprintf(ct->interface, sizeof(ct->interface), "%s", ctx->conf.interface);
    ct->self_sync.s_addr = 0;
    for (size_t i = 0; i < ctx->conf.n_members; i++) {
        if (!strcmp(ctx->conf.members[i].id, ctx->conf.self)) {
            ct->self_sync = ctx->conf.members[i].sync_address;
            break;
        }
    }

    size_t n = 0;
    for (size_t i = 0; i < ctx->conf.n_members && n < HADC_MEMBERS_MAX; i++) {
        const hadc_member_t *m = &ctx->conf.members[i];
        if (!strcmp(m->id, ctx->conf.self))
            continue;
        hadc_ct_peer_t *p = &ct->peers[n];
        bool same = p->in_use && !strcmp(p->id, m->id) && p->addr.s_addr == m->sync_address.s_addr;
        if (!same) {
            close_peer(p);
            memset(p, 0, sizeof(*p));
            p->fd = -1;
            snprintf(p->id, sizeof(p->id), "%s", m->id);
            p->addr = m->sync_address;
        }
        p->in_use = true;
        n++;
    }
    for (size_t i = n; i < HADC_MEMBERS_MAX; i++) {
        close_peer(&ct->peers[i]);
        memset(&ct->peers[i], 0, sizeof(ct->peers[i]));
        ct->peers[i].fd = -1;
    }
    ct->n_peers = n;
    refresh_owned_addrs_locked(ct, ctx);
    ct->st.enabled = ct->enabled;
    ct->st.peer_count = (int)n;
    ct->st.originating = ct->enabled && ct->role == HADC_ROLE_MASTER;
    ct->st.replica = ct->enabled && ct->role == HADC_ROLE_SLAVE;
}

static int ensure_listen(struct hadc_conntrack *ct)
{
    if (!ct->enabled || ct->self_sync.s_addr == 0 || ct->port == 0)
        return -1;
    if (ct->listen_fd >= 0)
        return 0;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(ct->port), .sin_addr = ct->self_sync };
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    ct->listen_fd = fd;
    hadc_info("conntrack: listening on %s:%u", inet_ntoa(ct->self_sync), (unsigned)ct->port);
    return 0;
}

static int peer_flush_partial(struct hadc_conntrack *ct, hadc_ct_peer_t *p)
{
    if (!p || p->fd < 0) return -1;
    while (p->tx_partial_off < p->tx_partial_len) {
        ssize_t w = write(p->fd, p->tx_partial + p->tx_partial_off, p->tx_partial_len - p->tx_partial_off);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                return 0;
            return -1;
        }
        if (w == 0) return 0;
        p->tx_partial_off += (size_t)w;
        p->last_send_ms = now_ms();
    }
    if (!p->tx_partial_counted) {
        ct->st.tx_frames++;
        if (p->tx_partial_type == HADC_CT_MSG_SNAPSHOT_ENTRY ||
            p->tx_partial_type == HADC_CT_MSG_UPSERT ||
            p->tx_partial_type == HADC_CT_MSG_DELETE)
            ct->st.tx_entries++;
        p->tx_partial_counted = true;
    }
    p->tx_partial_len = 0;
    p->tx_partial_off = 0;
    p->tx_partial_type = 0;
    p->tx_partial_counted = false;
    return 1;
}

static int send_frame(struct hadc_conntrack *ct, hadc_ct_peer_t *p, uint8_t type, uint16_t flags, const void *payload, uint32_t len)
{
    if (!p || p->fd < 0)
        return -1;
    if (len > HADC_CT_MAX_FRAME)
        return -1;
    if (p->tx_partial_len > 0) {
        int pr = peer_flush_partial(ct, p);
        if (pr <= 0) return pr; /* pending/error; cannot interleave */
    }
    hadc_ct_hdr_t h;
    memset(&h, 0, sizeof(h));
    h.magic[0] = HADC_CT_MAGIC0; h.magic[1] = HADC_CT_MAGIC1;
    h.magic[2] = HADC_CT_MAGIC2; h.magic[3] = HADC_CT_MAGIC3;
    h.ver = HADC_CT_VER;
    h.type = type;
    h.flags = htons(flags);
    h.len = htonl(len);
    h.seq = htonl(++p->tx_seq);
    h.ack_seq = htonl(p->rx_seq);
    memcpy(p->tx_partial, &h, sizeof(h));
    if (len && payload) memcpy(p->tx_partial + sizeof(h), payload, len);
    p->tx_partial_len = sizeof(h) + len;
    p->tx_partial_off = 0;
    p->tx_partial_type = type;
    p->tx_partial_counted = false;
    return peer_flush_partial(ct, p);
}

static void txq_clear(hadc_ct_peer_t *p)
{
    p->txq_head = p->txq_tail = p->txq_count = 0;
}

static int txq_push(struct hadc_conntrack *ct, hadc_ct_peer_t *p, uint8_t type, uint16_t flags,
                    const void *payload, uint32_t len)
{
    if (!p) return -1;
    if (len > sizeof(((hadc_ct_txop_t*)0)->data)) return -1;
    uint32_t cap = ct->max_queue_entries ? ct->max_queue_entries : HADC_CT_TXQ_MAX;
    if (cap > HADC_CT_TXQ_MAX) cap = HADC_CT_TXQ_MAX;
    if (p->txq_count >= HADC_CT_TXQ_MAX || p->txq_count >= cap) {
        ct->st.queue_drops++;
        p->drops++;
        p->need_resync = true;
        return -1;
    }
    hadc_ct_txop_t *op = &p->txq[p->txq_tail];
    op->type = type;
    op->flags = flags;
    op->len = len;
    if (len && payload) memcpy(op->data, payload, len);
    p->txq_tail = (p->txq_tail + 1) % HADC_CT_TXQ_MAX;
    p->txq_count++;
    return 0;
}

static void peer_flush_tx(struct hadc_conntrack *ct, hadc_ct_peer_t *p)
{
    if (!p || !p->connected) return;
    if (p->tx_partial_len > 0) {
        int pr = peer_flush_partial(ct, p);
        if (pr <= 0) {
            if (pr < 0) close_peer(p);
            return;
        }
    }
    while (p->txq_count > 0) {
        hadc_ct_txop_t *op = &p->txq[p->txq_head];
        int rc = send_frame(ct, p, op->type, op->flags, op->len ? op->data : NULL, op->len);
        if (rc < 0) { close_peer(p); return; }
        if (rc == 0) return; /* would block or partial buffered */
        p->txq_head = (p->txq_head + 1) % HADC_CT_TXQ_MAX;
        p->txq_count--;
    }
}

static int queue_entry(struct hadc_conntrack *ct, hadc_ct_peer_t *p, uint8_t type, const hadc_ct_entry_v1_t *e)
{
    return txq_push(ct, p, type, 0, e, (uint32_t)sizeof(*e));
}

static int send_json_msg(struct hadc_conntrack *ct, hadc_ct_peer_t *p, uint8_t type, uint16_t flags, json_t *obj)
{
    char *txt = json_dumps(obj, JSON_COMPACT);
    json_decref(obj);
    if (!txt)
        return -1;
    int rc = send_frame(ct, p, type, flags, txt, (uint32_t)strlen(txt));
    free(txt);
    return rc;
}

static void ct_entry_log_tuple(char *buf, size_t buflen, const hadc_ct_entry_v1_t *e)
{
    if (!buf || buflen == 0) return;
    char os[INET_ADDRSTRLEN] = "", od[INET_ADDRSTRLEN] = "", rs[INET_ADDRSTRLEN] = "", rd[INET_ADDRSTRLEN] = "";
    struct in_addr a;
    a.s_addr = e->orig_src; inet_ntop(AF_INET, &a, os, sizeof(os));
    a.s_addr = e->orig_dst; inet_ntop(AF_INET, &a, od, sizeof(od));
    a.s_addr = e->repl_src; inet_ntop(AF_INET, &a, rs, sizeof(rs));
    a.s_addr = e->repl_dst; inet_ntop(AF_INET, &a, rd, sizeof(rd));
    snprintf(buf, buflen, "proto=%u orig=%s:%u->%s:%u reply=%s:%u->%s:%u zone=%u mark=0x%x",
             (unsigned)e->proto,
             os[0]?os:"0.0.0.0", (unsigned)ntohs(e->orig_sport),
             od[0]?od:"0.0.0.0", (unsigned)ntohs(e->orig_dport),
             rs[0]?rs:"0.0.0.0", (unsigned)ntohs(e->repl_sport),
             rd[0]?rd:"0.0.0.0", (unsigned)ntohs(e->repl_dport),
             (unsigned)e->zone, (unsigned)e->mark);
}

static void send_hello(struct hadc_conntrack *ct, hadc_ct_peer_t *p)
{
    if (!p || !p->connected || p->hello_sent)
        return;
    if (p->tx_partial_len > 0) {
        int pr = peer_flush_partial(ct, p);
        if (pr <= 0) { if (pr < 0) close_peer(p); return; }
    }
    json_t *o = json_pack("{s:s,s:s,s:i,s:b,s:b,s:i}", "node", ct->self,
                          "role", ct->role == HADC_ROLE_MASTER ? "master" : "slave",
                          "gen", (int)ct->generation,
                          "snapshot", ct->snapshot_on_connect,
                          "ipv4_only", true,
                          "ver", HADC_CT_VER);
    int rc = send_json_msg(ct, p, HADC_CT_MSG_HELLO, 0, o);
    if (rc > 0)
        p->hello_sent = true;
    else if (rc < 0)
        close_peer(p);
    /* rc==0 means buffered/blocked, retry later without marking sent */
}


static hadc_ct_peer_t *peer_by_addr(struct hadc_conntrack *ct, struct in_addr a)
{
    for (size_t i = 0; i < ct->n_peers; i++)
        if (ct->peers[i].in_use && ct->peers[i].addr.s_addr == a.s_addr)
            return &ct->peers[i];
    return NULL;
}

static bool same_tuple(const hadc_ct_entry_v1_t *a, const hadc_ct_entry_v1_t *b)
{
    return a->proto == b->proto &&
           a->orig_src == b->orig_src && a->orig_dst == b->orig_dst &&
           a->orig_sport == b->orig_sport && a->orig_dport == b->orig_dport &&
           a->repl_src == b->repl_src && a->repl_dst == b->repl_dst &&
           a->repl_sport == b->repl_sport && a->repl_dport == b->repl_dport &&
           a->zone == b->zone;
}

static void stage_or_apply(struct hadc_conntrack *ct, const hadc_ct_entry_v1_t *e, bool del)
{
    /* Shadow state kept for staged apply on promotion and as replica cache. */
    for (size_t i = 0; i < ct->n_shadow; i++) {
        hadc_ct_shadow_ent_t *s = &ct->shadow[i];
        if (!s->valid) continue;
        if (!same_tuple(&s->e, e)) continue;
        if (del) { s->valid = false; ct->st.applied_entries++; }
        else { s->e = *e; s->updated_ms = now_ms(); s->seen_in_snapshot = ct->rx_snapshot_active; ct->st.applied_entries++; }
        return;
    }
    if (del)
        return;
    for (size_t i = 0; i < ct->n_shadow; i++) {
        if (!ct->shadow[i].valid) {
            ct->shadow[i].e = *e;
            ct->shadow[i].updated_ms = now_ms();
            ct->shadow[i].valid = true;
            ct->shadow[i].seen_in_snapshot = ct->rx_snapshot_active;
            ct->st.applied_entries++;
            return;
        }
    }
    if (ct->n_shadow < HADC_CT_SHADOW_MAX) {
        hadc_ct_shadow_ent_t *s = &ct->shadow[ct->n_shadow++];
        s->e = *e;
        s->updated_ms = now_ms();
        s->valid = true;
        s->seen_in_snapshot = ct->rx_snapshot_active;
        ct->st.applied_entries++;
    } else {
        /* bounded table full: evict oldest valid entry as best-effort */
        size_t victim = SIZE_MAX;
        uint64_t oldest = UINT64_MAX;
        for (size_t i = 0; i < ct->n_shadow; i++) {
            if (!ct->shadow[i].valid) { victim = i; break; }
            if (ct->shadow[i].updated_ms < oldest) { oldest = ct->shadow[i].updated_ms; victim = i; }
        }
        if (victim != SIZE_MAX) {
            ct->shadow[victim].e = *e;
            ct->shadow[victim].updated_ms = now_ms();
            ct->shadow[victim].valid = true;
            ct->shadow[victim].seen_in_snapshot = ct->rx_snapshot_active;
            ct->st.applied_entries++;
            ct->st.dropped_entries++; /* indicates churn/eviction pressure */
        } else {
            ct->st.dropped_entries++;
        }
    }
}

static void handle_frame(struct hadc_conntrack *ct, hadc_ct_peer_t *p, const hadc_ct_hdr_t *h, const uint8_t *payload)
{
    uint32_t len = ntohl(h->len);
    p->rx_seq = ntohl(h->seq);
    p->last_seen_ms = now_ms();
    ct->st.rx_frames++;
    if (h->type == HADC_CT_MSG_HELLO) {
        p->hello_ok = true;
        if (payload && len > 0) {
            json_error_t jerr; json_t *jo = json_loadb((const char *)payload, len, 0, &jerr);
            if (jo) {
                const char *pr = json_string_value(json_object_get(jo, "role"));
                p->peer_is_master = pr && strcmp(pr, "master") == 0;
                json_decref(jo);
            }
        }
        json_t *o = json_pack("{s:s,s:s,s:i,s:s}", "node", ct->self,
                              "role", ct->role == HADC_ROLE_MASTER ? "master" : "slave",
                              "gen", (int)ct->generation, "ack", "ok");
        (void)send_json_msg(ct, p, HADC_CT_MSG_HELLO_ACK, 0, o);
        if (ct->role == HADC_ROLE_SLAVE && ct->snapshot_on_connect)
            (void)send_json_msg(ct, p, HADC_CT_MSG_RESYNC_REQ, HADC_CT_F_RESYNC, json_object());
        return;
    }
    if (h->type == HADC_CT_MSG_HELLO_ACK) {
        p->hello_ok = true;
        if (payload && len > 0) {
            json_error_t jerr; json_t *jo = json_loadb((const char *)payload, len, 0, &jerr);
            if (jo) {
                const char *pr = json_string_value(json_object_get(jo, "role"));
                p->peer_is_master = pr && strcmp(pr, "master") == 0;
                json_decref(jo);
            }
        }
        return;
    }
    if (h->type == HADC_CT_MSG_KEEPALIVE) return;
    if (h->type == HADC_CT_MSG_SNAPSHOT_BEGIN) {
        if (ct->role == HADC_ROLE_SLAVE) {
            ct->rx_snapshot_active = true;
            for (size_t i = 0; i < ct->n_shadow; i++)
                ct->shadow[i].seen_in_snapshot = false;
        }
        return;
    }
    if (h->type == HADC_CT_MSG_SNAPSHOT_END) {
        if (ct->role == HADC_ROLE_SLAVE && ct->rx_snapshot_active) {
            for (size_t i = 0; i < ct->n_shadow; i++) {
                hadc_ct_shadow_ent_t *s = &ct->shadow[i];
                if (!s->valid || s->seen_in_snapshot)
                    continue;
                /* master missed this entry: keep/validate and report fix to master */
                char desc[256];
                ct_entry_log_tuple(desc, sizeof(desc), &s->e);
                hadc_warn("conntrack: master snapshot missing entry, keeping and reporting fix: %s", desc);
                s->seen_in_snapshot = true; /* avoid repeated reports for this snapshot cycle */
                s->updated_ms = now_ms();
                if (ct->slave_apply_mode == HADC_CT_APPLY_IMMEDIATE) {
                    if (ct->ctnl_fd < 0) (void)ctnl_open(ct);
                    (void)ctnl_apply_entry(ct, &s->e, false);
                }
                bool reported = false;
                for (size_t pi = 0; pi < ct->n_peers; pi++) {
                    hadc_ct_peer_t *mp = &ct->peers[pi];
                    if (!mp->connected || !mp->hello_ok || !mp->peer_is_master)
                        continue;
                    int rc = send_frame(ct, mp, HADC_CT_MSG_UPSERT, 0, &s->e, sizeof(s->e));
                    if (rc >= 0)
                        reported = true;
                }
                if (!reported)
                    ct->st.dropped_entries++;
            }
            ct->rx_snapshot_active = false;
        }
        return;
    }
    if (h->type == HADC_CT_MSG_RESYNC_REQ) {
        p->need_resync = true;
        p->resyncs++;
        ct->st.resync_count++;
        return;
    }
    if ((h->type == HADC_CT_MSG_SNAPSHOT_ENTRY || h->type == HADC_CT_MSG_UPSERT || h->type == HADC_CT_MSG_DELETE) &&
        ntohl(h->len) >= sizeof(hadc_ct_entry_v1_t)) {
        const hadc_ct_entry_v1_t *e = (const hadc_ct_entry_v1_t *)payload;
        const char *reason = NULL;
        bool del = (h->type == HADC_CT_MSG_DELETE) || (e->flags & 8);
        if (ct->role == HADC_ROLE_SLAVE) {
            bool ok = classify_non_local(ct, e, &reason) || !ct->non_local_only;
            if (ok || del) {
                if (ct->slave_apply_mode == HADC_CT_APPLY_IMMEDIATE) {
                    if (ct->ctnl_fd < 0) (void)ctnl_open(ct);
                    (void)ctnl_apply_entry(ct, e, del);
                }
                stage_or_apply(ct, e, del);
                ct->st.rx_entries++;
            } else {
                ct->st.dropped_entries++;
                hadc_dbg("conntrack: drop rx entry from %s reason=%s", p->id, reason ? reason : "filtered");
            }
        } else if (ct->role == HADC_ROLE_MASTER && (h->type == HADC_CT_MSG_UPSERT || h->type == HADC_CT_MSG_DELETE)) {
            bool ok = classify_non_local(ct, e, &reason) || !ct->non_local_only;
            if (ok || del) {
                char desc[256];
                ct_entry_log_tuple(desc, sizeof(desc), e);
                hadc_info("conntrack: master accepted %s fix from %s: %s",
                          del ? "delete" : "upsert", p->id, desc);
                if (ct->ctnl_fd < 0) (void)ctnl_open(ct);
                (void)ctnl_apply_entry(ct, e, del);
                master_queue_entry_all(ct, del ? HADC_CT_MSG_DELETE : HADC_CT_MSG_UPSERT, e, p);
                ct->st.rx_entries++;
            } else {
                ct->st.dropped_entries++;
                hadc_dbg("conntrack: drop master fix from %s reason=%s", p->id, reason ? reason : "filtered");
            }
        }
        return;
    }
}

static void peer_rx(struct hadc_conntrack *ct, hadc_ct_peer_t *p)
{
    for (;;) {
        ssize_t r = read(p->fd, p->rxbuf + p->rxlen, sizeof(p->rxbuf) - p->rxlen);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                return;
            close_peer(p);
            return;
        }
        if (r == 0) { close_peer(p); return; }
        p->rxlen += (size_t)r;
        while (p->rxlen >= sizeof(hadc_ct_hdr_t)) {
            hadc_ct_hdr_t *h = (hadc_ct_hdr_t *)p->rxbuf;
            if (h->magic[0] != HADC_CT_MAGIC0 || h->magic[1] != HADC_CT_MAGIC1 ||
                h->magic[2] != HADC_CT_MAGIC2 || h->magic[3] != HADC_CT_MAGIC3 || h->ver != HADC_CT_VER) {
                close_peer(p);
                return;
            }
            uint32_t len = ntohl(h->len);
            if (len > HADC_CT_MAX_FRAME) { close_peer(p); return; }
            size_t total = sizeof(hadc_ct_hdr_t) + len;
            if (p->rxlen < total)
                break;
            handle_frame(ct, p, h, p->rxbuf + sizeof(hadc_ct_hdr_t));
            memmove(p->rxbuf, p->rxbuf + total, p->rxlen - total);
            p->rxlen -= total;
        }
    }
}

static void accept_peer(struct hadc_conntrack *ct)
{
    for (;;) {
        struct sockaddr_in sa; socklen_t sl = sizeof(sa);
        int fd = accept4(ct->listen_fd, (struct sockaddr *)&sa, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                return;
            return;
        }
        hadc_ct_peer_t *p = peer_by_addr(ct, sa.sin_addr);
        if (!p) {
            close(fd);
            continue; /* only configured cluster peers */
        }
        if (p->fd >= 0)
            close_peer(p);
        p->fd = fd;
        p->connected = true;
        p->accepted = true;
        p->rxlen = 0;
        p->hello_sent = false;
        p->hello_ok = false;
        p->last_seen_ms = now_ms();
        hadc_info("conntrack: accepted peer %s from %s", p->id, inet_ntoa(sa.sin_addr));
    }
}

static void ensure_master_connections(struct hadc_conntrack *ct)
{
    if (!ct->enabled || ct->role != HADC_ROLE_MASTER)
        return;
    uint64_t t = now_ms();
    for (size_t i = 0; i < ct->n_peers; i++) {
        hadc_ct_peer_t *p = &ct->peers[i];
        if (!p->in_use || p->connected || p->fd >= 0)
            continue;
        if (t - p->last_connect_ms < 2000)
            continue;
        p->last_connect_ms = t;
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0)
            continue;
        int one = 1;
        (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(ct->port), .sin_addr = p->addr };
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0 || errno == EINPROGRESS) {
            p->fd = fd;
            p->connected = (errno == 0);
        } else {
            close(fd);
        }
    }
}

static void master_maybe_send_snapshot(struct hadc_conntrack *ct, hadc_ct_peer_t *p)
{
    if (!p || !p->connected || !p->hello_ok) return;
    if (p->tx_partial_len > 0) return; /* don't interleave markers while frame pending */
    if (!p->need_resync && !(ct->snapshot_on_connect && p->tx_seq <= 1))
        return;
    /* Avoid joining a dump mid-stream: wait for idle dump and no active snapshots */
    if (ct->ctnl_dump_pending) { p->need_resync = true; return; }
    for (size_t i = 0; i < ct->n_peers; i++) {
        if (&ct->peers[i] != p && ct->peers[i].connected && ct->peers[i].snapshot_active) {
            p->need_resync = true;
            return;
        }
    }

    txq_clear(p);
    int rc = send_json_msg(ct, p, HADC_CT_MSG_SNAPSHOT_BEGIN, HADC_CT_F_SNAPSHOT | HADC_CT_F_RESYNC,
                           json_pack("{s:i}", "gen", (int)ct->generation));
    if (rc <= 0) { if (rc < 0) close_peer(p); else p->need_resync = true; return; }
    p->snapshot_active = true;
    p->need_resync = false;
    ct->st.resync_count++;
    if (ct->ctnl_fd < 0) (void)ctnl_open(ct);
    if (ct->ctnl_fd >= 0) {
        if (ctnl_request_dump(ct) < 0)
            p->need_resync = true;
    } else {
        p->need_resync = true;
    }
}

static void *conntrack_thread_main(void *arg)
{
    struct hadc_conntrack *ct = arg;
    hadc_info("conntrack: worker thread started (ipv4-only, binary TCP sync)");

    while (1) {
        pthread_mutex_lock(&ct->lock);
        bool stop = ct->stop;
        pthread_mutex_unlock(&ct->lock);
        if (stop)
            break;

        pthread_mutex_lock(&ct->lock);
        uint64_t now = now_ms();
        if (ct->enabled && ct->rtnl_fd < 0) {
            if (rtnl_open(ct) == 0)
                rtnl_dump_addrs(ct);
        } else if (!ct->enabled && ct->rtnl_fd >= 0) {
            close(ct->rtnl_fd);
            ct->rtnl_fd = -1;
        }
        if (ct->enabled && ct->ctnl_fd < 0)
            (void)ctnl_open(ct);
        else if (!ct->enabled && ct->ctnl_fd >= 0)
            ctnl_close(ct);
        /* if dump stuck without completion for too long, recover (best-effort) */
        if (ct->ctnl_dump_pending && ct->ctnl_fd >= 0 && ct->ctnl_dump_start_ms > 0 &&
            now - ct->ctnl_dump_start_ms > 30000) {
            hadc_warn("conntrack: ct dump timeout, recovering");
            ctnl_close(ct);
        }
        if (ct->helper_cache_refresh_s &&
            now - ct->last_helper_refresh_ms >= (uint64_t)ct->helper_cache_refresh_s * 1000) {
            int sip_mode = ct->sip_mode;
            pthread_mutex_unlock(&ct->lock);
            bool nl_helper = (sip_mode != HADC_CT_SIP_OFF) ? probe_cthelper_sip() : false;
            pthread_mutex_lock(&ct->lock);
            refresh_helper_cache_locked(ct, nl_helper);
        }
        if (now - ct->last_addr_refresh_ms >= 10000)
            refresh_owned_addrs_locked(ct, ct->ctx);
        prune_shadow(ct, now);
        ctnl_apply_retry_tick(ct, now);

        if (ct->enabled) {
            (void)ensure_listen(ct);
        } else {
            if (ct->listen_fd >= 0) { close(ct->listen_fd); ct->listen_fd = -1; }
            if (ct->ctnl_fd >= 0) ctnl_close(ct);
            ct->n_shadow = 0;
            ct->rx_snapshot_active = false;
            ct->slave_resync_requested = false;
            for (size_t i = 0; i < ct->n_peers; i++) {
                ct->peers[i].need_resync = false;
                if (ct->peers[i].fd >= 0 || ct->peers[i].connected)
                    close_peer(&ct->peers[i]);
            }
        }

        if (ct->apply_shadow_pending && ct->role == HADC_ROLE_MASTER) {
            ct->apply_shadow_pending = false;
            apply_shadow_all(ct);
        }
        if (ct->enabled && ct->role == HADC_ROLE_MASTER && ct->resync_interval_s > 0 &&
            now - ct->last_resync_ms >= (uint64_t)ct->resync_interval_s * 1000) {
            for (size_t i = 0; i < ct->n_peers; i++) ct->peers[i].need_resync = true;
            ct->last_resync_ms = now;
            ct->st.resync_count++;
        }

        ensure_master_connections(ct);
        for (size_t i = 0; i < ct->n_peers; i++) {
            hadc_ct_peer_t *p = &ct->peers[i];
            if (p->fd >= 0 && !p->connected) {
                int err = 0; socklen_t el = sizeof(err);
                if (getsockopt(p->fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) {
                    p->connected = true;
                    p->last_seen_ms = now;
                } else if (err != 0 && err != EINPROGRESS) {
                    close_peer(p);
                }
            }
            if (p->connected)
                send_hello(ct, p);
            if (p->connected && p->hello_ok && ct->role == HADC_ROLE_MASTER)
                master_maybe_send_snapshot(ct, p);
            if (p->connected && p->hello_ok && ct->role == HADC_ROLE_SLAVE && ct->slave_resync_requested &&
                p->tx_partial_len == 0) {
                int rc = send_json_msg(ct, p, HADC_CT_MSG_RESYNC_REQ, HADC_CT_F_RESYNC, json_object());
                if (rc >= 0)
                    ct->slave_resync_requested = false;
            }
            if (p->connected && p->hello_ok)
                peer_flush_tx(ct, p);
            if (p->connected && p->hello_ok && p->tx_partial_len == 0 && now - p->last_send_ms > 5000)
                (void)send_json_msg(ct, p, HADC_CT_MSG_KEEPALIVE, 0, json_pack("{s:i}", "t", (int)now));
        }

        /* if a dump finished, close snapshot for peers after queued entries flush */
        if (ct->role == HADC_ROLE_MASTER && !ct->ctnl_dump_pending) {
            for (size_t i = 0; i < ct->n_peers; i++) {
                hadc_ct_peer_t *p = &ct->peers[i];
                if (!p->connected || !p->snapshot_active) continue;
                if (p->txq_count > 0 || p->tx_partial_len > 0) continue;
                int rc = send_json_msg(ct, p, HADC_CT_MSG_SNAPSHOT_END, HADC_CT_F_SNAPSHOT,
                                       json_pack("{s:i}", "gen", (int)ct->generation));
                if (rc > 0) p->snapshot_active = false;
                else if (rc < 0) close_peer(p);
            }
            /* if another peer requested resync while dump was running, start next dump */
            bool any_need = false, any_active = false;
            for (size_t i = 0; i < ct->n_peers; i++) {
                if (ct->peers[i].connected && ct->peers[i].snapshot_active) any_active = true;
                if (ct->peers[i].connected && ct->peers[i].hello_ok && ct->peers[i].need_resync) any_need = true;
            }
            if (any_need && !any_active && ct->ctnl_fd >= 0)
                (void)ctnl_request_dump(ct);
        }

        int peers_connected = 0;
        for (size_t i = 0; i < ct->n_peers; i++)
            if (ct->peers[i].connected)
                peers_connected++;
        ct->st.peers_connected = peers_connected;
        ct->st.running = ct->enabled;
        pthread_mutex_unlock(&ct->lock);

        struct pollfd pfds[1 + 1 + 1 + 1 + HADC_MEMBERS_MAX];
        nfds_t nfds = 0;
        pfds[nfds++] = (struct pollfd){ .fd = ct->wakefd, .events = POLLIN };
        pthread_mutex_lock(&ct->lock);
        if (ct->listen_fd >= 0)
            pfds[nfds++] = (struct pollfd){ .fd = ct->listen_fd, .events = POLLIN };
        if (ct->rtnl_fd >= 0)
            pfds[nfds++] = (struct pollfd){ .fd = ct->rtnl_fd, .events = POLLIN };
        if (ct->ctnl_fd >= 0)
            pfds[nfds++] = (struct pollfd){ .fd = ct->ctnl_fd, .events = POLLIN };
        for (size_t i = 0; i < ct->n_peers; i++) {
            if (ct->peers[i].fd >= 0) {
                short ev = POLLIN | POLLERR | POLLHUP;
                if (ct->peers[i].txq_count > 0 || ct->peers[i].tx_partial_len > 0) ev |= POLLOUT;
                pfds[nfds++] = (struct pollfd){ .fd = ct->peers[i].fd, .events = ev };
            }
        }
        pthread_mutex_unlock(&ct->lock);

        (void)poll(pfds, nfds, 250);
        if (pfds[0].revents & POLLIN)
            drain_wake(ct->wakefd);

        pthread_mutex_lock(&ct->lock);
        if (ct->rtnl_fd >= 0) {
            struct pollfd r = { .fd = ct->rtnl_fd, .events = POLLIN };
            if (poll(&r, 1, 0) > 0 && (r.revents & POLLIN))
                drain_rtnl(ct, ct->ctx);
        }
        if (ct->ctnl_fd >= 0) {
            struct pollfd r = { .fd = ct->ctnl_fd, .events = POLLIN };
            if (poll(&r, 1, 0) > 0 && (r.revents & POLLIN))
                drain_ctnl(ct);
        }
        if (ct->listen_fd >= 0) {
            struct pollfd l = { .fd = ct->listen_fd, .events = POLLIN };
            if (poll(&l, 1, 0) > 0 && (l.revents & POLLIN))
                accept_peer(ct);
        }
        for (size_t i = 0; i < ct->n_peers; i++) {
            hadc_ct_peer_t *p = &ct->peers[i];
            if (p->fd < 0)
                continue;
            short ev = POLLIN | POLLERR | POLLHUP;
            if (p->txq_count > 0 || p->tx_partial_len > 0) ev |= POLLOUT;
            struct pollfd chk = { .fd = p->fd, .events = ev };
            if (poll(&chk, 1, 0) > 0) {
                if (chk.revents & (POLLERR | POLLHUP)) { close_peer(p); continue; }
                if (chk.revents & POLLIN) peer_rx(ct, p);
                if (p->connected && (chk.revents & POLLOUT)) peer_flush_tx(ct, p);
            }
        }
        pthread_mutex_unlock(&ct->lock);
    }

    pthread_mutex_lock(&ct->lock);
    if (ct->listen_fd >= 0) { close(ct->listen_fd); ct->listen_fd = -1; }
    if (ct->rtnl_fd >= 0) { close(ct->rtnl_fd); ct->rtnl_fd = -1; }
    ctnl_close(ct);
    for (size_t i = 0; i < ct->n_peers; i++)
        close_peer(&ct->peers[i]);
    ct->running = false;
    ct->st.running = false;
    ct->st.originating = false;
    ct->st.replica = false;
    ct->st.peers_connected = 0;
    pthread_mutex_unlock(&ct->lock);
    hadc_info("conntrack: worker thread stopped");
    return NULL;
}

int hadc_conntrack_init(hadc_ctx_t *ctx)
{
    if (!ctx)
        return -1;
    struct hadc_conntrack *ct = calloc(1, sizeof(*ct));
    if (!ct)
        return -1;
    ct->ctx = ctx;
    ct->wakefd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    ct->listen_fd = -1;
    ct->rtnl_fd = -1;
    ct->ctnl_fd = -1;
    ct->apply_shadow_pending = false;
    if (ct->wakefd < 0) {
        free(ct);
        return -1;
    }
    pthread_mutex_init(&ct->lock, NULL);
    for (size_t i = 0; i < HADC_MEMBERS_MAX; i++)
        ct->peers[i].fd = -1;
    ct->apply_shadow_pending = false;
    ct->generation = 1;
    ct->last_resync_ms = now_ms();
    bool nl_init = ctx->conf.conntrack_sync.helpers.sip != HADC_CT_SIP_OFF ? probe_cthelper_sip() : false;
    pthread_mutex_lock(&ct->lock);
    snapshot_config_locked(ct, ctx);
    refresh_helper_cache_locked(ct, nl_init);
    pthread_mutex_unlock(&ct->lock);
    ctx->conntrack = ct;
    return 0;
}

int hadc_conntrack_start(hadc_ctx_t *ctx)
{
    struct hadc_conntrack *ct = ctx ? ctx->conntrack : NULL;
    if (!ct)
        return 0;
    pthread_mutex_lock(&ct->lock);
    bool need = ct->enabled && !ct->thread_started;
    pthread_mutex_unlock(&ct->lock);
    if (!need)
        return 0;
    if (pthread_create(&ct->thread, NULL, conntrack_thread_main, ct) != 0) {
        hadc_err("conntrack: failed to start worker thread: %s", strerror(errno));
        return -1;
    }
    pthread_mutex_lock(&ct->lock);
    ct->thread_started = true;
    pthread_mutex_unlock(&ct->lock);
    return 0;
}

void hadc_conntrack_stop(hadc_ctx_t *ctx)
{
    struct hadc_conntrack *ct = ctx ? ctx->conntrack : NULL;
    if (!ct)
        return;
    pthread_mutex_lock(&ct->lock);
    ct->stop = true;
    bool started = ct->thread_started;
    pthread_mutex_unlock(&ct->lock);
    ct_wake(ct);
    if (started)
        pthread_join(ct->thread, NULL);
    pthread_mutex_lock(&ct->lock);
    ct->thread_started = false;
    pthread_mutex_unlock(&ct->lock);
}

void hadc_conntrack_shutdown(hadc_ctx_t *ctx)
{
    struct hadc_conntrack *ct = ctx ? ctx->conntrack : NULL;
    if (!ct)
        return;
    hadc_conntrack_stop(ctx);
    if (ct->wakefd >= 0)
        close(ct->wakefd);
    pthread_mutex_destroy(&ct->lock);
    free(ct);
    ctx->conntrack = NULL;
}

void hadc_conntrack_notify_role(hadc_ctx_t *ctx, hadc_role_t old_role, hadc_role_t new_role)
{
    struct hadc_conntrack *ct = ctx ? ctx->conntrack : NULL;
    (void)old_role;
    if (!ct)
        return;
    pthread_mutex_lock(&ct->lock);
    snapshot_config_locked(ct, ctx);
    ct->role = new_role;
    ct->st.originating = ct->enabled && new_role == HADC_ROLE_MASTER;
    ct->st.replica = ct->enabled && new_role == HADC_ROLE_SLAVE;
    if (new_role == HADC_ROLE_MASTER) {
        ct->generation++;
        ct->slave_resync_requested = false;
        ct->rx_snapshot_active = false;
        if (old_role == HADC_ROLE_SLAVE)
            ct->apply_shadow_pending = true; /* deferred to worker */
    } else {
        ct->ctnl_dump_pending = false;
        ct->slave_resync_requested = true; /* validate/fix against new master */
        for (size_t i = 0; i < ct->n_peers; i++)
            ct->peers[i].snapshot_active = false;
    }
    pthread_mutex_unlock(&ct->lock);
    hadc_info("conntrack: role %s -> %s", old_role == HADC_ROLE_MASTER ? "master" : "slave",
              new_role == HADC_ROLE_MASTER ? "master" : "slave");
    ct_wake(ct);
}

void hadc_conntrack_notify_config(hadc_ctx_t *ctx)
{
    struct hadc_conntrack *ct = ctx ? ctx->conntrack : NULL;
    if (!ct)
        return;
    bool nl_cfg = false;
    if (ctx->conf.conntrack_sync.helpers.sip != HADC_CT_SIP_OFF)
        nl_cfg = probe_cthelper_sip();
    pthread_mutex_lock(&ct->lock);
    snapshot_config_locked(ct, ctx);
    refresh_helper_cache_locked(ct, nl_cfg);
    pthread_mutex_unlock(&ct->lock);
    ct_wake(ct);
}

void hadc_conntrack_notify_vip(hadc_ctx_t *ctx)
{
    hadc_conntrack_notify_config(ctx);
}

int hadc_conntrack_resync(hadc_ctx_t *ctx)
{
    struct hadc_conntrack *ct = ctx ? ctx->conntrack : NULL;
    if (!ct || !ct->enabled)
        return -1;
    pthread_mutex_lock(&ct->lock);
    if (ct->role == HADC_ROLE_MASTER) {
        for (size_t i = 0; i < ct->n_peers; i++)
            ct->peers[i].need_resync = true;
    } else {
        ct->slave_resync_requested = true;
    }
    ct->st.resync_count++;
    ct->last_resync_ms = now_ms();
    pthread_mutex_unlock(&ct->lock);
    ct_wake(ct);
    return 0;
}

void hadc_conntrack_get_status(const hadc_ctx_t *ctx, hadc_ct_status_t *out)
{
    struct hadc_conntrack *ct = ctx ? ctx->conntrack : NULL;
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!ct)
        return;
    pthread_mutex_lock((pthread_mutex_t *)&ct->lock);
    *out = ct->st;
    uint32_t sh = 0;
    for (size_t i = 0; i < ct->n_shadow; i++)
        if (ct->shadow[i].valid) sh++;
    out->shadow_entries = sh;
    pthread_mutex_unlock((pthread_mutex_t *)&ct->lock);
}

char *hadc_conntrack_status_json(const hadc_ctx_t *ctx)
{
    hadc_ct_status_t st;
    hadc_conntrack_get_status(ctx, &st);
    const char *sip = st.sip_helper == HADC_CT_HELPER_AVAILABLE ? "available"
                    : st.sip_helper == HADC_CT_HELPER_UNAVAILABLE ? "unavailable"
                    : st.sip_helper == HADC_CT_HELPER_DEGRADED ? "degraded" : "unknown";
    json_t *o = json_pack(
        "{s:b,s:b,s:b,s:b,s:i,s:i,s:I,s:I,s:I,s:I,s:I,s:I,s:I,s:I,s:i,s:s,s:s}",
        "enabled", st.enabled, "running", st.running, "originating", st.originating,
        "replica", st.replica, "peer_count", st.peer_count, "peers_connected", st.peers_connected,
        "tx_frames", (json_int_t)st.tx_frames, "rx_frames", (json_int_t)st.rx_frames,
        "tx_entries", (json_int_t)st.tx_entries, "rx_entries", (json_int_t)st.rx_entries,
        "applied_entries", (json_int_t)st.applied_entries, "dropped_entries", (json_int_t)st.dropped_entries,
        "resync_count", (json_int_t)st.resync_count, "queue_drops", (json_int_t)st.queue_drops,
        "shadow_entries", (int)st.shadow_entries,
        "sip_helper", sip, "sip_helper_reason", st.sip_helper_reason);
    char *txt = json_dumps(o, JSON_PRESERVE_ORDER | JSON_COMPACT);
    json_decref(o);
    return txt;
}
