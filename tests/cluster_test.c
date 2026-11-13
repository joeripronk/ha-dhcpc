/* Cluster self-monitor (P0-3): the heartbeat send cadence runs on its own thread
 * so a stall it detects is a real process-wide stop, not main-loop contention.
 * The thread never mutates shared state; on a genuine stall it wakes the main
 * loop via the self-pipe, and the main loop performs the demote. This test drives
 * that seam directly (simulating the thread's stall signal) and checks the
 * main-loop guard: demote only for a master in a real cluster, not for a slave
 * and not during a graceful restart. */
#define _GNU_SOURCE

#include <fcntl.h>
#include <pthread.h>
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

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts); /* peer last_seen_ms is monotonic (hadc_now_ms) */
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static uint64_t realtime_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts); /* graceful_restart_until_ms is realtime */
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void setup(hadc_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    snprintf(ctx->conf.self, sizeof(ctx->conf.self), "A");
    ctx->conf.priority = 10;
    ctx->conf.default_role_master = true;
    ctx->conf.cluster.heartbeat_ms = 10;
    ctx->conf.cluster.election_deadline_ms = 60;
    ctx->conf.cluster.self_demote_gap_ms = 100;
    ctx->conf.n_members = 2;
    snprintf(ctx->conf.members[0].id, HADC_NODE_ID_MAX, "A");
    ctx->conf.members[0].priority = 10;
    snprintf(ctx->conf.members[1].id, HADC_NODE_ID_MAX, "B");
    ctx->conf.members[1].priority = 5;
    snprintf(ctx->conf.designated_master, sizeof(ctx->conf.designated_master), "A");
    ctx->n_peers = 2;
    snprintf(ctx->peers[0].id, HADC_NODE_ID_MAX, "A");
    snprintf(ctx->peers[1].id, HADC_NODE_ID_MAX, "B");
    ctx->udp_fd = -1; /* transport closed: sends are guarded no-ops */
    if (pthread_mutex_init(&ctx->hb_lock, NULL) != 0)
        return;
    if (pipe2(ctx->hb_selfpipe, O_NONBLOCK | O_CLOEXEC) != 0)
        return;
    hadc_cluster_set_role_hook(role_hook, ctx);
}

static void signal_stall(hadc_ctx_t *ctx)
{
    char b = 1;
    (void)!write(ctx->hb_selfpipe[1], &b, 1);
}

int main(void)
{
    hadc_ctx_t ctx;

    /* A master in a real cluster, with a live peer, must demote when the heartbeat
     * thread reports a stall. Mark B seen so it is the handoff target. */
    setup(&ctx);
    ctx.role = HADC_ROLE_MASTER;
    ctx.peers[1].last_seen_ms = now_ms(); /* B live: the handoff target */
    signal_stall(&ctx);
    hadc_cluster_selfpipe_ready(&ctx);
    if (hook_count != 1)
        return fail("stalled master did not demote on the main loop");
    if (hook_old != HADC_ROLE_MASTER || hook_new != HADC_ROLE_SLAVE)
        return fail("self-demotion role transition wrong");
    if (ctx.role != HADC_ROLE_SLAVE)
        return fail("role not settled to slave");
    if (strcmp(ctx.conf.designated_master, "B") != 0)
        return fail("did not hand the role to the live peer");

    /* A slave has nothing to demote: the main-loop guard must not fire. */
    hook_count = 0;
    setup(&ctx);
    ctx.role = HADC_ROLE_SLAVE;
    signal_stall(&ctx);
    hadc_cluster_selfpipe_ready(&ctx);
    if (hook_count != 0)
        return fail("slave demoted on the main loop");
    if (ctx.role != HADC_ROLE_SLAVE)
        return fail("slave role changed");

    /* During a graceful restart no role switch is allowed. */
    hook_count = 0;
    setup(&ctx);
    ctx.role = HADC_ROLE_MASTER;
    ctx.peers[1].alive = true;
    ctx.graceful_restart_until_ms = realtime_ms() + 100000;
    signal_stall(&ctx);
    hadc_cluster_selfpipe_ready(&ctx);
    if (hook_count != 0)
        return fail("demoted during a graceful restart");
    if (ctx.role != HADC_ROLE_MASTER)
        return fail("master role changed during graceful restart");

    printf("cluster_test: OK\n");
    return 0;
}
