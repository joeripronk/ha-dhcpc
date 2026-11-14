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
    TASSERT(h.ver == 1, "ver");
}

static void test_shadow_stage_prune_and_compact(void) {
    struct hadc_conntrack ct;
    memset(&ct, 0, sizeof(ct));
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
    prune_shadow(&ct, now_ms());
    TASSERT(ct.n_shadow == 0, "delete compacted");
}

int main(void) {
    test_ct_entry_tuple_format();
    test_build_apply_msg_create_delete();
    test_hdr_wire();
    test_shadow_stage_prune_and_compact();
    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("conntrack_test: OK\n");
    return 0;
}
