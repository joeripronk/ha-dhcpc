/* Serialized maintenance worker (plan step 3).
 *
 * The main epoll loop must stay responsive to DHCP/ctl/cluster packets, so the
 * heavy/IO maintenance work runs on this dedicated thread instead:
 *   - the periodic netlink audit/reconcile, gwping, gateway-mac poll, graceful
 *     keepalive and routing reconcile;
 *   - the fsync-heavy persist write, whose JSON snapshot is built on the
 *     calling thread (a consistent view) and only the file IO is offloaded.
 *
 * Tasks are queued by the main loop (or by maintenance itself) and executed
 * strictly serially. hadc_maint_lock serializes the executor/routing/ping/
 * persist state between this worker and the main loop; it is recursive so the
 * public executor/routing entry points can nest (routing_reconcile -> apply).
 */
#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/log.h"
#include "ha-dhcpc/routing.h"
#include "internal.h"

typedef struct hadc_maint_task {
    struct hadc_maint_task *next;
    hadc_maint_fn_t fn;
    void *arg;
} hadc_maint_task_t;

static pthread_mutex_t g_state_lock; /* serializes executor/routing/ping/persist */
static pthread_mutex_t g_qlock;      /* guards the task queue */
static pthread_cond_t g_qcond;
static hadc_maint_task_t *g_head, *g_tail;
static pthread_t g_thread;
static bool g_started;
static bool g_stop;
static bool g_tick_pending;
static hadc_ctx_t *g_ctx;

void hadc_maint_lock(void)
{
    if (!g_started)
        return; /* single-threaded startup/shutdown: nothing to serialize */
    pthread_mutex_lock(&g_state_lock);
}

void hadc_maint_unlock(void)
{
    if (!g_started)
        return;
    pthread_mutex_unlock(&g_state_lock);
}

bool hadc_maint_running(void)
{
    return g_started;
}

static void *worker_main(void *arg)
{
    (void)arg;
    hadc_info("maintenance: worker thread started");
    for (;;) {
        pthread_mutex_lock(&g_qlock);
        while (!g_head && !g_stop)
            pthread_cond_wait(&g_qcond, &g_qlock);
        if (g_stop && !g_head) {
            pthread_mutex_unlock(&g_qlock);
            break;
        }
        hadc_maint_task_t *t = g_head;
        g_head = t->next;
        if (!g_head)
            g_tail = NULL;
        pthread_mutex_unlock(&g_qlock);
        if (t->fn)
            t->fn(t->arg);
        free(t);
    }
    hadc_info("maintenance: worker thread stopped");
    return NULL;
}

int hadc_maint_start(hadc_ctx_t *ctx)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    if (pthread_mutex_init(&g_state_lock, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        hadc_err("maintenance: state lock init failed");
        return -1;
    }
    pthread_mutexattr_destroy(&attr);
    if (pthread_mutex_init(&g_qlock, NULL) != 0 ||
        pthread_cond_init(&g_qcond, NULL) != 0) {
        hadc_err("maintenance: queue lock init failed");
        return -1;
    }
    g_head = g_tail = NULL;
    g_stop = false;
    g_tick_pending = false;
    g_ctx = ctx;
    if (pthread_create(&g_thread, NULL, worker_main, NULL) != 0) {
        hadc_err("maintenance: pthread_create failed");
        return -1;
    }
    g_started = true;
    return 0;
}

void hadc_maint_stop(void)
{
    if (!g_started)
        return;
    pthread_mutex_lock(&g_qlock);
    g_stop = true;
    pthread_cond_broadcast(&g_qcond);
    pthread_mutex_unlock(&g_qlock);
    pthread_join(g_thread, NULL);
    g_started = false;
    /* drain any tasks left (should be none) */
    while (g_head) {
        hadc_maint_task_t *t = g_head;
        g_head = t->next;
        free(t);
    }
    g_tail = NULL;
    pthread_mutex_destroy(&g_qlock);
    pthread_cond_destroy(&g_qcond);
    pthread_mutex_destroy(&g_state_lock);
}

int hadc_maint_post_fn(hadc_maint_fn_t fn, void *arg)
{
    if (!g_started || !fn)
        return -1;
    hadc_maint_task_t *t = calloc(1, sizeof(*t));
    if (!t)
        return -1;
    t->fn = fn;
    t->arg = arg;
    pthread_mutex_lock(&g_qlock);
    if (g_stop) {
        pthread_mutex_unlock(&g_qlock);
        free(t);
        return -1;
    }
    t->next = NULL;
    if (g_tail)
        g_tail->next = t;
    else
        g_head = t;
    g_tail = t;
    pthread_cond_broadcast(&g_qcond);
    pthread_mutex_unlock(&g_qlock);
    return 0;
}

/* The periodic maintenance tick. Coalesced: a queued tick is not duplicated. */
static void tick_task(void *arg)
{
    hadc_ctx_t *ctx = arg;

    pthread_mutex_lock(&g_qlock);
    g_tick_pending = false;
    pthread_mutex_unlock(&g_qlock);

    hadc_executor_audit_tick(ctx);
    hadc_gwping_tick(ctx);
    hadc_cluster_gateway_mac_refresh(ctx);
    hadc_cluster_graceful_keepalive(ctx);
    hadc_routing_reconcile(ctx, "periodic");
}

int hadc_maint_post_tick(hadc_ctx_t *ctx)
{
    (void)ctx; /* use stored g_ctx for consistency */
    pthread_mutex_lock(&g_qlock);
    bool pending = g_tick_pending || g_stop || !g_started;
    if (!pending)
        g_tick_pending = true;
    pthread_mutex_unlock(&g_qlock);
    if (pending)
        return 0;
    if (hadc_maint_post_fn(tick_task, g_ctx) != 0) {
        pthread_mutex_lock(&g_qlock);
        g_tick_pending = false;
        pthread_mutex_unlock(&g_qlock);
        return -1;
    }
    return 0;
}
