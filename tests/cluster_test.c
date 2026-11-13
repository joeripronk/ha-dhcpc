/* Cluster self-monitor (P0-3): a master that cannot send heartbeats within a
 * full election deadline steps down on its own, handing the role to the best
 * live peer, instead of waiting for a peer to steal it in a contested election.
 * The tick cadence is the daemon's heartbeat timer; the test drives the tick
 * directly and uses a real sleep larger than the deadline to simulate a stall. */
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/config.h"
#include "ha-dhcpc/types.h"
#include "internal.h"

static int hook_count;
static hadc_role_t hook_old, hook_new;

static void role_hook(void *arg, hadc_role_t old_role, hadc_role_t new_role)
{
    (void)arg;
    hook_count++;
    hook_old = old_role;
    hook_new = new_role;
}

static int fail(const char *what)
{
    printf("cluster_test: FAIL (%s)\n", what);
    return 1;
}

static void msleep(int ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

int main(void)
{
    hadc_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    snprintf(ctx.conf.self, sizeof(ctx.conf.self), "A");
    ctx.conf.priority = 10;
    ctx.conf.default_role_master = true;
    ctx.conf.cluster.heartbeat_ms = 10;
    ctx.conf.cluster.election_deadline_ms = 60;
    ctx.conf.cluster.self_demote_gap_ms = 100;
    ctx.conf.n_members = 2;
    snprintf(ctx.conf.members[0].id, HADC_NODE_ID_MAX, "A");
    ctx.conf.members[0].priority = 10;
    snprintf(ctx.conf.members[1].id, HADC_NODE_ID_MAX, "B");
    ctx.conf.members[1].priority = 5;
    snprintf(ctx.conf.designated_master, sizeof(ctx.conf.designated_master), "A");

    ctx.n_peers = 2;
    snprintf(ctx.peers[0].id, HADC_NODE_ID_MAX, "A");
    snprintf(ctx.peers[1].id, HADC_NODE_ID_MAX, "B");

    ctx.role = HADC_ROLE_MASTER;
    ctx.udp_fd = -1; /* transport closed: sends are guarded no-ops */

    hadc_cluster_set_role_hook(role_hook, &ctx);

    /* First tick establishes the last-heartbeat baseline: no role change. */
    hadc_cluster_heartbeat(&ctx);
    if (ctx.role != HADC_ROLE_MASTER)
        return fail("first tick must not change role");
    if (hook_count != 0)
        return fail("first tick fired the role hook");

    /* The master's loop stalls past heartbeat_ms + gap (10 + 100 = 110 ms): on
     * the next tick it must demote itself and hand off to the only live peer (B),
     * before a peer would steal it at the election deadline. Mark B seen just
     * before the tick so it is inside the peer liveness window when the demotion
     * picks the handoff target. */
    msleep(150); /* > heartbeat_ms + self_demote_gap_ms (110 ms) */
    ctx.peers[1].last_seen_ms = (uint64_t)hadc_now_ms(); /* B is alive */
    hadc_cluster_heartbeat(&ctx);

    if (hook_count != 1)
        return fail("stalled master did not self-demote");
    if (hook_old != HADC_ROLE_MASTER || hook_new != HADC_ROLE_SLAVE)
        return fail("self-demotion role transition wrong");
    if (ctx.role != HADC_ROLE_SLAVE)
        return fail("role not settled to slave");
    if (strcmp(ctx.conf.designated_master, "B") != 0)
        return fail("did not hand the role to the live peer");

    printf("cluster_test: OK\n");
    return 0;
}
