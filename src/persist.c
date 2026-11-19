/* Persistence: cluster view JSON, atomic rename + fsync (plan §3/§8). */

#include <arpa/inet.h>
#include <errno.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ha-dhcpc/persist.h"
#include "ha-dhcpc/log.h"
#include "internal.h"

static char g_path[HADC_PATH_MAX];

int hadc_persist_init(hadc_ctx_t *ctx, const char *path)
{
    snprintf(g_path, sizeof(g_path), "%s", path);
    snprintf(ctx->persist_path, sizeof(ctx->persist_path), "%s", path);
    return 0;
}

int hadc_persist_load(hadc_ctx_t *ctx, hadc_persist_view_t *out)
{
    (void)ctx;
    memset(out, 0, sizeof(*out));
    FILE *f = fopen(g_path, "r");
    if (!f) {
        if (errno != ENOENT)
            hadc_warn("persist: open %s: %s", g_path, strerror(errno));
        return 0; /* no file yet = fresh start */
    }
    json_error_t jerr;
    json_t *root = json_loadf(f, 0, &jerr);
    fclose(f);
    if (!root) {
        hadc_warn("persist: %s: %s (treating as fresh start)", g_path, jerr.text);
        return 0;
    }
    out->found = true;
    json_t *v;
    if ((v = json_object_get(root, "role")) && json_is_string(v))
        out->role = hadc_role_from_name(json_string_value(v));
    else
        out->role = HADC_ROLE_UNKNOWN;
    if ((v = json_object_get(root, "master_id")) && json_is_string(v))
        snprintf(out->master_id, sizeof(out->master_id), "%s",
                 json_string_value(v));
    if ((v = json_object_get(root, "lease_version")) && json_is_integer(v))
        out->lease_version = (uint64_t)json_integer_value(v);
    if ((v = json_object_get(root, "acked_version")) && json_is_integer(v))
        out->acked_version = (uint64_t)json_integer_value(v);
    if ((v = json_object_get(root, "graceful_restart_until_ms")) && json_is_integer(v))
        out->graceful_restart_until_ms = (uint64_t)json_integer_value(v);
    if ((v = json_object_get(root, "ospf_seq")) && json_is_integer(v))
        out->ospf_seq = (uint64_t)json_integer_value(v);
    v = json_object_get(root, "ospf_self_lsas");
    if (v && json_is_array(v)) {
        out->ospf_lsas = (void *)json_incref(v); /* owned by the view */
    }

    json_t *lj = json_object_get(root, "lease");
    hadc_lease_from_json(lj, &out->lease);

    /* Absolute UTC anchors need no downtime recalculation; clocks are the
     * source of truth on restart. */

    json_decref(root);
    return 0;
}

/* Serialize the cluster view. Built on the calling thread so it observes a
 * consistent ctx snapshot (the main loop owns that state); only the blocking
 * file IO is offloaded to the maintenance worker. */
static char *persist_build_json(hadc_ctx_t *ctx)
{
    /* Timers are absolute UTC anchors; persist them as-is. */
    json_t *lj = hadc_lease_to_json(&ctx->lease);
    if (!lj)
        return NULL;
    json_t *o = json_pack("{s:s, s:s, s:I, s:I, s:s, s:s, s:I, s:I, s:o}", "role",
                          hadc_role_name(ctx->role), "master_id", ctx->conf.designated_master,
                          "lease_version", (json_int_t)ctx->lease.version, "acked_version",
                          (json_int_t)ctx->acked_version, "interface", ctx->conf.interface,
                          "conf_sha256", ctx->conf.sha256, "saved_at_utc",
                          (json_int_t)time(NULL), "graceful_restart_until_ms",
                          (json_int_t)ctx->graceful_restart_until_ms, "lease", lj);
    if (!o) {
        json_decref(lj);
        return NULL;
    }
    /* Self-originated OSPF LSAs: persisted so a restart re-adopts the exact
     * same LSDB entries (sequence continues, content identical) and the LSDB
     * never moves; see ospf.c. */
    {
        json_t *arr = json_array();
        hadc_ospf_collect_self_lsas(arr);
        json_object_set_new(o, "ospf_self_lsas", arr);
        json_object_set_new(o, "ospf_seq", json_integer((json_int_t)hadc_ospf_next_seq()));
    }
    char *txt = json_dumps(o, JSON_PRESERVE_ORDER | JSON_COMPACT);
    json_decref(o);
    return txt;
}

/* Atomic rename + fsync. */
static int persist_write_file(const char *path, const char *json)
{
    char tmp[HADC_PATH_MAX];
    size_t len = strlen(json);

    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) {
        hadc_err("persist: fopen %s: %s", tmp, strerror(errno));
        return -1;
    }
    if (fwrite(json, 1, len, f) != len) {
        hadc_err("persist: write %s failed: %s", tmp, strerror(errno));
        fclose(f);
        return -1;
    }
    fsync(fileno(f));
    fclose(f);
    if (rename(tmp, path) != 0) {
        hadc_err("persist: rename to %s: %s", path, strerror(errno));
        return -1;
    }
    return 0;
}

typedef struct {
    char *path;
    char *json;
} persist_write_req_t;

static void persist_write_task(void *arg)
{
    persist_write_req_t *r = arg;
    (void)persist_write_file(r->path, r->json);
    free(r->path);
    free(r->json);
    free(r);
}

int hadc_persist_save(hadc_ctx_t *ctx)
{
    char *json = persist_build_json(ctx);
    if (!json)
        return -1;
    if (hadc_maint_running()) {
        /* Offload the fsync/rename to the maintenance worker; the serialized
         * snapshot above is already consistent, so ordering is preserved. */
        persist_write_req_t *r = calloc(1, sizeof(*r));
        if (!r) {
            free(json);
            return -1;
        }
        r->path = strdup(g_path);
        r->json = json;
        if (!r->path || hadc_maint_post_fn(persist_write_task, r) != 0) {
            free(r->path);
            free(r->json);
            free(r);
            return -1;
        }
        return 0;
    }
    int rc = persist_write_file(g_path, json);
    free(json);
    return rc;
}
