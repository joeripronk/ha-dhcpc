/* Persistence: cluster view JSON, atomic rename + fsync (plan §3/§8). */
#define _GNU_SOURCE

#include <errno.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ha-dhcpc/persist.h"
#include "ha-dhcpc/log.h"
#include "internal.h"

static char g_path[PATH_MAX];

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
        out->role = !strcmp(json_string_value(v), "master")      ? HADC_ROLE_MASTER
                   : !strcmp(json_string_value(v), "slave")      ? HADC_ROLE_SLAVE
                                                                  : HADC_ROLE_UNKNOWN;
    if ((v = json_object_get(root, "lease_version")) && json_is_integer(v))
        out->lease_version = (uint64_t)json_integer_value(v);
    if ((v = json_object_get(root, "acked_version")) && json_is_integer(v))
        out->acked_version = (uint64_t)json_integer_value(v);
    json_decref(root);
    return 0;
}

int hadc_persist_save(hadc_ctx_t *ctx)
{
    json_t *o = json_pack("{s:s, s:I, s:I, s:s}", "role",
                          ctx->role == HADC_ROLE_MASTER ? "master"
                          : ctx->role == HADC_ROLE_SLAVE ? "slave"
                                                         : "unknown",
                          "lease_version", (json_int_t)ctx->lease.version, "acked_version",
                          (json_int_t)0, "interface", ctx->conf.interface);
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_path);
    FILE *f = fopen(tmp, "w");
    if (!f) {
        hadc_err("persist: fopen %s: %s", tmp, strerror(errno));
        json_decref(o);
        return -1;
    }
    if (json_dumpf(o, f, JSON_PRESERVE_ORDER | JSON_COMPACT) != 0) {
        hadc_err("persist: write %s failed", tmp);
        fclose(f);
        json_decref(o);
        return -1;
    }
    fsync(fileno(f));
    fclose(f);
    json_decref(o);
    if (rename(tmp, g_path) != 0) {
        hadc_err("persist: rename to %s: %s", g_path, strerror(errno));
        return -1;
    }
    return 0;
}
