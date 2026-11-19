#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "ha-dhcpc/log.h"

/* stub logging backend used by conntrack.c macros */
void hadc_log(hadc_log_level_t level, const char *fmt, ...) { (void)level; (void)fmt; }
void hadc_log_set_level(hadc_log_level_t level) { (void)level; }
long long hadc_now_ms(void) { return 0; }

#include "../src/conntrack.c"

static int failures = 0;
#define TASSERT(cond, msg) do { if (!(cond)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); failures++; } } while(0)

static void test_ct_entry_tuple_format(void) {
    hadc_ct_entry_v1_t e;
    memset(&e, 0, sizeof(e));
    e.proto = IPPROTO_TCP;
    inet_pton(AF_INET, "10.0.0.1", &e.orig_src);
    inet_pton(AF_INET, "10.0.0.2", &e.orig_dst);
    inet_pton(AF_INET, "10.0.0.2", &e.repl_src);
    inet_pton(AF_INET, "1.2.3.4", &e.repl_dst);
    e.orig_sport = htons(1111);
    e.orig_dport = htons(80);
    e.repl_sport = htons(80);
    e.repl_dport = htons(2222);
    e.zone = 7; e.mark = 0x1234;
    char buf[256];
    ct_entry_log_tuple(buf, sizeof(buf), &e);
    TASSERT(strstr(buf, "proto=6") != NULL, "proto in tuple log");
    TASSERT(strstr(buf, "10.0.0.1:1111") != NULL, "orig in tuple log");
    TASSERT(strstr(buf, "1.2.3.4:2222") != NULL, "reply in tuple log");
    TASSERT(strstr(buf, "zone=7") != NULL, "zone in tuple log");
}

static void test_build_apply_msg_create_delete(void) {
    hadc_ct_entry_v1_t e;
    memset(&e, 0, sizeof(e));
    e.family = AF_INET; e.addr_len = 4; e.proto = IPPROTO_TCP; e.tcp_state = 3;
    inet_pton(AF_INET, "192.168.1.10", &e.orig_src);
    inet_pton(AF_INET, "8.8.8.8", &e.orig_dst);
    inet_pton(AF_INET, "8.8.8.8", &e.repl_src);
    inet_pton(AF_INET, "203.0.113.5", &e.repl_dst);
    e.orig_sport = htons(40000); e.orig_dport = htons(443);
    e.repl_sport = htons(443); e.repl_dport = htons(50000);
    e.timeout_s = 60; e.status = IPS_CONFIRMED | IPS_SEEN_REPLY;
    char msg[1024];
    size_t len = ctnl_build_apply_msg(msg, sizeof(msg), &e, false, true, 42);
    TASSERT(len > sizeof(struct nlmsghdr)+sizeof(struct nfgenmsg), "build create msg");
    struct nlmsghdr *nh = (struct nlmsghdr *)msg;
    TASSERT(nh->nlmsg_len == (uint32_t)len, "nlmsg_len");
    TASSERT(nh->nlmsg_seq == 42, "seq");
    TASSERT(nh->nlmsg_flags & NLM_F_ACK, "ack flag");
    TASSERT(nh->nlmsg_flags & NLM_F_CREATE, "create flag for new entry");
    TASSERT((nh->nlmsg_type & 0xff) == IPCTNL_MSG_CT_NEW, "new msg type");

    size_t len2 = ctnl_build_apply_msg(msg, sizeof(msg), &e, false, false, 43);
    nh = (struct nlmsghdr *)msg;
    TASSERT(len2 > 0, "build replace msg");
    TASSERT(!(nh->nlmsg_flags & NLM_F_CREATE), "no create flag for replace");
    TASSERT((nh->nlmsg_type & 0xff) == IPCTNL_MSG_CT_NEW, "replace uses CT_NEW");

    size_t len3 = ctnl_build_apply_msg(msg, sizeof(msg), &e, true, false, 44);
    nh = (struct nlmsghdr *)msg;
    TASSERT(len3 > 0, "build delete msg");
    TASSERT((nh->nlmsg_type & 0xff) == IPCTNL_MSG_CT_DELETE, "delete msg type");
    TASSERT(!(nh->nlmsg_flags & NLM_F_CREATE), "no create on delete");
}

static void test_hdr_wire(void) {
    hadc_ct_hdr_t h;
    memset(&h, 0, sizeof(h));
    h.magic[0]=HADC_CT_MAGIC0; h.magic[1]=HADC_CT_MAGIC1; h.magic[2]=HADC_CT_MAGIC2; h.magic[3]=HADC_CT_MAGIC3;
    h.ver = HADC_CT_VER; h.type = HADC_CT_MSG_UPSERT; h.flags = htons(0);
    h.len = htonl(sizeof(hadc_ct_entry_v1_t));
    h.seq = htonl(7);
    TASSERT(h.magic[0]=='H' && h.magic[1]=='C' && h.magic[2]=='T' && h.magic[3]=='1', "magic");
    TASSERT(h.ver == 4, "ver");
}

static void test_shadow_stage_prune_and_compact(void) {
    struct hadc_conntrack ct;
    memset(&ct, 0, sizeof(ct));
    shadow_hash_init(&ct);
    ct.max_entry_age_s = 10;
    hadc_ct_entry_v1_t e;
    memset(&e, 0, sizeof(e));
    e.family = AF_INET; e.addr_len = 4; e.proto = IPPROTO_UDP;
    inet_pton(AF_INET, "10.1.1.1", &e.orig_src);
    inet_pton(AF_INET, "10.1.1.2", &e.orig_dst);
    inet_pton(AF_INET, "10.1.1.2", &e.repl_src);
    inet_pton(AF_INET, "8.8.8.8", &e.repl_dst);
    e.orig_sport = htons(1111); e.orig_dport = htons(53);
    e.repl_sport = htons(53); e.repl_dport = htons(2222);

    ct.rx_snapshot_active = true;
    stage_or_apply(&ct, &e, false);
    TASSERT(ct.n_shadow == 1 && ct.shadow[0].valid && ct.shadow[0].seen_in_snapshot, "stage entry during snapshot");

    ct.rx_snapshot_active = false;
    stage_or_apply(&ct, &e, false);
    TASSERT(ct.n_shadow == 1, "dedupe same tuple");
    TASSERT(ct.st.applied_entries == 2, "applied count increments on update");

    hadc_ct_entry_v1_t e2 = e;
    e2.orig_sport = htons(3333); e2.repl_dport = htons(4444);
    stage_or_apply(&ct, &e2, false);
    TASSERT(ct.n_shadow == 2, "second distinct entry");

    ct.shadow[0].updated_ms = 100;
    ct.shadow[1].updated_ms = 8000;
    prune_shadow(&ct, 11100); /* age first (>10s), keep second */
    TASSERT(!ct.shadow[0].valid && ct.shadow[1].valid, "old entry pruned");
    TASSERT(ct.n_shadow == 2, "no compaction when tail valid");

    prune_shadow(&ct, 20000); /* age second */
    TASSERT(!ct.shadow[1].valid, "second pruned");
    TASSERT(ct.n_shadow == 0, "tail compaction");

    stage_or_apply(&ct, &e, false);
    TASSERT(ct.n_shadow == 1 && ct.shadow[0].valid, "restage after compact");
    stage_or_apply(&ct, &e, true);
    TASSERT(ct.n_shadow == 1 && !ct.shadow[0].valid, "delete marks invalid");
    prune_shadow(&ct, (uint64_t)hadc_now_ms());
    TASSERT(ct.n_shadow == 0, "delete compacted");
}

static void test_shadow_eviction_when_full(void) {
    struct hadc_conntrack ct;
    memset(&ct, 0, sizeof(ct));
    shadow_hash_init(&ct);
    ct.max_entry_age_s = 0;
    for (size_t i = 0; i < HADC_CT_SHADOW_MAX; i++) {
        hadc_ct_entry_v1_t e;
        memset(&e, 0, sizeof(e));
        e.family = AF_INET; e.addr_len = 4; e.proto = IPPROTO_TCP;
        e.orig_src = htonl(0x0a000001u); e.orig_dst = htonl(0x0a000002u);
        e.repl_src = e.orig_dst; e.repl_dst = htonl(0x08080808u);
        e.orig_sport = htons((uint16_t)(1000 + i)); e.orig_dport = htons(80);
        e.repl_sport = htons(80); e.repl_dport = htons((uint16_t)(2000 + i));
        stage_or_apply(&ct, &e, false);
        ct.shadow[i].updated_ms = (uint64_t)(i + 1); /* oldest = 1 at index 0 */
    }
    TASSERT(ct.n_shadow == HADC_CT_SHADOW_MAX, "shadow filled");
    uint64_t drops_before = ct.st.dropped_entries;
    hadc_ct_entry_v1_t en;
    memset(&en, 0, sizeof(en));
    en.family = AF_INET; en.addr_len = 4; en.proto = IPPROTO_TCP;
    en.orig_src = htonl(0x0a000099u); en.orig_dst = htonl(0x0a000002u);
    en.repl_src = en.orig_dst; en.repl_dst = htonl(0x08080808u);
    en.orig_sport = htons(9999); en.orig_dport = htons(80);
    en.repl_sport = htons(80); en.repl_dport = htons(8888);
    stage_or_apply(&ct, &en, false);
    TASSERT(ct.n_shadow == HADC_CT_SHADOW_MAX, "shadow size stable on eviction");
    TASSERT(ct.st.dropped_entries == drops_before + 1, "eviction counted as drop pressure");
    TASSERT(ct.shadow[0].valid, "victim slot reused");
    TASSERT(ct.shadow[0].e.orig_sport == htons(9999), "oldest entry evicted/replaced");
}

static void test_apply_pending_alloc_find(void) {
    struct hadc_conntrack ct;
    memset(&ct, 0, sizeof(ct));
    ct.ctnl_fd = -1;
    ct.ctnl_apply_seq = 10;
    for (int i = 0; i < HADC_CT_APPLY_PENDING_MAX; i++) {
        hadc_ct_apply_pending_t *ap = ctnl_alloc_apply(&ct);
        TASSERT(ap != NULL, "alloc pending slot");
        ap->in_use = true;
        ap->seq = (uint32_t)(100 + i);
    }
    TASSERT(ctnl_alloc_apply(&ct) == NULL, "no slot when full");
    hadc_ct_apply_pending_t *f = ctnl_find_apply(&ct, 105);
    TASSERT(f != NULL && f->seq == 105, "find pending by seq");
    TASSERT(ctnl_find_apply(&ct, 9999) == NULL, "missing seq not found");
    TASSERT(ctnl_find_apply(&ct, 0) == NULL, "seq 0 not found");
    f->in_use = false;
    hadc_ct_apply_pending_t *r = ctnl_alloc_apply(&ct);
    TASSERT(r != NULL, "reuse freed slot");
}


static void test_parse_ct_nat_and_expectation(void) {
    /* synthetic conntrack NEW with NAT flag and seqadj markers */
    char msg[1024]; memset(msg,0,sizeof(msg));
    struct nlmsghdr *nh = (struct nlmsghdr*)msg;
    struct nfgenmsg *nf = (struct nfgenmsg*)(msg + NLMSG_ALIGN(sizeof(*nh)));
    nh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK<<8) | IPCTNL_MSG_CT_NEW;
    nf->nfgen_family = AF_INET; nf->version = NFNETLINK_V0;
    size_t off = NLMSG_ALIGN(sizeof(*nh)) + NLMSG_ALIGN(sizeof(*nf));
    uint32_t os=inet_addr("10.0.0.5"), od=inet_addr("8.8.8.8"), rs=inet_addr("8.8.8.8"), rd=inet_addr("203.0.113.9");
    TASSERT(build_tuple_nla(msg,sizeof(msg),&off,CTA_TUPLE_ORIG,os,od,IPPROTO_TCP,htons(1111),htons(80)), "orig tuple");
    TASSERT(build_tuple_nla(msg,sizeof(msg),&off,CTA_TUPLE_REPLY,rs,rd,IPPROTO_TCP,htons(80),htons(2222)), "reply tuple");
    uint32_t st = htonl(IPS_CONFIRMED|IPS_SEEN_REPLY|IPS_SRC_NAT_DONE);
    TASSERT(nla_put_u32(msg,sizeof(msg),&off,CTA_STATUS,st), "status");
    uint32_t corr = htonl(1);
    size_t sao = nla_nest_start(msg,sizeof(msg),&off,CTA_SEQ_ADJ_ORIG);
    TASSERT(sao!=(size_t)-1, "seqadj orig nest");
    TASSERT(nla_put_u32(msg,sizeof(msg),&off,CTA_SEQADJ_CORRECTION_POS,corr), "corr pos");
    nla_nest_end(msg,sao,off);
    nh->nlmsg_len = (uint32_t)off;
    hadc_ct_entry_v1_t e; bool del=false; uint32_t ct_id=0;
    TASSERT(parse_ct_entry_v4(nh,&e,&del,&ct_id), "parse nat ct");
    TASSERT(!del && e.ct_kind==0, "ct kind new");
    TASSERT(e.flags & 1, "nat flag from status/seqadj");

    /* synthetic expectation NEW */
    memset(msg,0,sizeof(msg)); nh=(struct nlmsghdr*)msg; nf=(struct nfgenmsg*)(msg + NLMSG_ALIGN(sizeof(*nh)));
    nh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK_EXP<<8) | IPCTNL_MSG_EXP_NEW;
    nf->nfgen_family = AF_INET; nf->version = NFNETLINK_V0;
    off = NLMSG_ALIGN(sizeof(*nh)) + NLMSG_ALIGN(sizeof(*nf));
    uint32_t es=inet_addr("203.0.113.5"), ed=inet_addr("10.0.0.5");
    TASSERT(build_tuple_nla(msg,sizeof(msg),&off,CTA_EXPECT_TUPLE,es,ed,IPPROTO_UDP,htons(5004),htons(6000)), "expect tuple");
    TASSERT(nla_put_u32(msg,sizeof(msg),&off,CTA_EXPECT_TIMEOUT,htonl(30)), "expect timeout");
    TASSERT(nla_put(msg,sizeof(msg),&off,CTA_EXPECT_HELP_NAME,"sip",4), "expect help");
    nh->nlmsg_len = (uint32_t)off;
    memset(&e,0,sizeof(e)); del=false; ct_id=0;
    TASSERT(parse_ct_entry_v4(nh,&e,&del,&ct_id), "parse expectation");
    TASSERT(e.ct_kind==1, "expect ct_kind");
    TASSERT(!del, "expect not delete");
    TASSERT(e.proto==IPPROTO_UDP, "expect proto");
    TASSERT(e.orig_sport==htons(5004) && e.orig_dport==htons(6000), "expect ports");
    TASSERT(e.timeout_s==30, "expect timeout parsed");
    TASSERT(e.helper_id==1, "expect sip helper");
    TASSERT(e.flags & 2, "expect related flag");
}

static void test_classify_non_local(void) {
    struct hadc_conntrack ct;
    memset(&ct, 0, sizeof(ct));
    ct.exclude_loopback = true;
    ct.non_local_only = true;
    ct.include_related = true;
    ct.owned_addrs[0].s_addr = inet_addr("203.0.113.10");
    ct.n_owned = 1;
    hadc_ct_entry_v1_t e;
    const char *reason = NULL;

    memset(&e, 0, sizeof(e));
    e.family = AF_INET; e.addr_len = 4;
    e.orig_src = inet_addr("127.0.0.1");
    e.orig_dst = inet_addr("8.8.8.8");
    e.repl_src = e.orig_dst; e.repl_dst = e.orig_src;
    TASSERT(!classify_non_local(&ct, &e, &reason), "loopback excluded");

    memset(&e, 0, sizeof(e));
    e.family = AF_INET; e.addr_len = 4;
    e.orig_src = inet_addr("10.0.0.5"); e.orig_dst = inet_addr("10.0.0.6");
    e.repl_src = e.orig_dst; e.repl_dst = e.orig_src; /* plain, unmanaged */
    TASSERT(!classify_non_local(&ct, &e, &reason), "unmanaged/non-local endpoints excluded");

    memset(&e, 0, sizeof(e));
    e.family = AF_INET; e.addr_len = 4;
    e.orig_src = inet_addr("203.0.113.10"); e.orig_dport = htons(1234);
    e.orig_dst = inet_addr("8.8.8.8");       e.orig_sport = 0; /* irrelevant */
    e.repl_src = inet_addr("8.8.8.8");       e.repl_dport = htons(1234);
    e.repl_dst = inet_addr("198.51.100.1");  e.repl_sport = htons(40000); /* NATed/public */
    e.flags |= 1;
    TASSERT(classify_non_local(&ct, &e, &reason), "owned NAT classified");

    memset(&e, 0, sizeof(e));
    e.family = AF_INET; e.addr_len = 4;
    e.orig_src = inet_addr("203.0.113.10"); e.orig_dst = inet_addr("203.0.113.20");
    e.repl_src = e.orig_dst; e.repl_dst = e.orig_src; /* local-only */
    TASSERT(!classify_non_local(&ct, &e, &reason), "local-only excluded");
}

int main(void) {
    test_ct_entry_tuple_format();
    test_build_apply_msg_create_delete();
    test_hdr_wire();
    test_shadow_stage_prune_and_compact();
    test_shadow_eviction_when_full();
    test_apply_pending_alloc_find();
    test_parse_ct_nat_and_expectation();
    test_classify_non_local();
    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("conntrack_test: OK\n");
    return 0;
}
