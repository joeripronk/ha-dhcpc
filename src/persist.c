/* Persistence: cluster view JSON, atomic rename + fsync (plan §3/§8). */
#define _GNU_SOURCE

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

static char g_path[PATH_MAX];

static hadc_lease_state_t name_to_state(const char *n)
{
    if (!strcmp(n, "NONE"))         return HADC_LEASE_NONE;
    if (!strcmp(n, "INIT-SELECT"))  return HADC_LEASE_INIT_SELECT;
    if (!strcmp(n, "INIT-REBOOT"))  return HADC_LEASE_INIT_REBOOT;
    if (!strcmp(n, "BOUND"))        return HADC_LEASE_BOUND;
    if (!strcmp(n, "RENEW"))        return HADC_LEASE_RENEW;
    if (!strcmp(n, "REBIND"))       return HADC_LEASE_REBIND;
    if (!strcmp(n, "RETAINED"))     return HADC_LEASE_RETAINED;
    return HADC_LEASE_NONE;
}

static void put_addr(json_t *obj, const char *key, struct in_addr a)
{
    char buf[64];
    json_object_set_new(obj, key, json_string(inet_ntop(AF_INET, &a, buf, sizeof(buf))));
}

static void get_addr(json_t *obj, const char *key, struct in_addr *out)
{
    json_t *v = json_object_get(obj, key);
    if (v && json_is_string(v))
        inet_pton(AF_INET, json_string_value(v), out);
}

static json_t *lease_json(const hadc_lease_t *l)
{
    char hex[65];
    json_t *dns = json_array();

    for (size_t i = 0; i < 32; i++)
        sprintf(hex + 2 * i, "%02x", l->config_hash[i]);
    for (size_t i = 0; i < l->n_dns; i++) {
        char buf[64];
        json_array_append_new(dns, json_string(inet_ntop(AF_INET, &l->dns[i], buf, sizeof(buf))));
    }
    json_t *o = json_pack("{s:s, s:b, s:s, s:s, s:s, s:s, s:o, s:I, s:I, s:I, s:I, s:s}",
                           "state", hadc_lease_state_name(l->state), "retention_active",
                           (int)l->retention_active, "address", "", "netmask", "", "gateway", "",
                           "server_id", "", "dns", dns, "t1_remaining_s",
                           (json_int_t)l->t1_remaining_s, "t2_remaining_s",
                           (json_int_t)l->t2_remaining_s, "t3_remaining_s",
                           (json_int_t)l->t3_remaining_s, "observed_at_utc",
                           (json_int_t)l->observed_at_utc, "config_hash", hex);
    if (!o) {
        json_decref(dns);
        return NULL;
    }
    put_addr(o, "address", l->address);
    put_addr(o, "netmask", l->netmask);
    put_addr(o, "gateway", l->gateway);
    put_addr(o, "server_id", l->server_id);
    if (l->gw_mac_valid) {
        char mac[2 * HADC_MAC_LEN + 1];
        for (size_t i = 0; i < HADC_MAC_LEN; i++)
            sprintf(mac + 2 * i, "%02x", l->gw_mac[i]);
        json_object_set_new(o, "gw_mac", json_string(mac));
    }
    return o;
}

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
        if (!strcmp(json_string_value(v), "master")) out->role = HADC_ROLE_MASTER;
        else if (!strcmp(json_string_value(v), "slave")) out->role = HADC_ROLE_SLAVE;
        else if (!strcmp(json_string_value(v), "promoting")) out->role = HADC_ROLE_PROMOTING;
        else if (!strcmp(json_string_value(v), "demoting")) out->role = HADC_ROLE_DEMOTING;
        else out->role = HADC_ROLE_UNKNOWN;
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
    if (lj && json_is_object(lj)) {
        hadc_lease_t *l = &out->lease;
        if ((v = json_object_get(lj, "state")) && json_is_string(v))
            l->state = name_to_state(json_string_value(v));
        if ((v = json_object_get(lj, "retention_active")) && json_is_boolean(v))
            l->retention_active = json_is_true(v);
        get_addr(lj, "address", &l->address);
        get_addr(lj, "netmask", &l->netmask);
        get_addr(lj, "gateway", &l->gateway);
        get_addr(lj, "server_id", &l->server_id);
        json_t *dns = json_object_get(lj, "dns");
        if (dns && json_is_array(dns)) {
            size_t idx;
            json_t *e;
            json_array_foreach(dns, idx, e) {
                if (json_is_string(e) && l->n_dns < HADC_DNS_MAX &&
                    inet_pton(AF_INET, json_string_value(e), &l->dns[l->n_dns]) == 1)
                    l->n_dns++;
            }
        }
        if ((v = json_object_get(lj, "t1_remaining_s")) && json_is_integer(v))
            l->t1_remaining_s = (uint32_t)json_integer_value(v);
        if ((v = json_object_get(lj, "t2_remaining_s")) && json_is_integer(v))
            l->t2_remaining_s = (uint32_t)json_integer_value(v);
        if ((v = json_object_get(lj, "t3_remaining_s")) && json_is_integer(v))
            l->t3_remaining_s = (uint32_t)json_integer_value(v);
        if ((v = json_object_get(lj, "observed_at_utc")) && json_is_integer(v))
            l->observed_at_utc = (long long)json_integer_value(v);
        if ((v = json_object_get(lj, "config_hash")) && json_is_string(v) &&
            strlen(json_string_value(v)) == 64) {
            for (size_t i = 0; i < 32; i++) {
                unsigned b;
                if (sscanf(json_string_value(v) + 2 * i, "%2x", &b) != 1)
                    break;
                l->config_hash[i] = (uint8_t)b;
            }
        }
        if ((v = json_object_get(lj, "gw_mac")) && json_is_string(v) &&
            strlen(json_string_value(v)) == 2 * HADC_MAC_LEN) {
            uint8_t mac[HADC_MAC_LEN];
            size_t i;
            for (i = 0; i < HADC_MAC_LEN; i++) {
                unsigned b;
                if (sscanf(json_string_value(v) + 2 * i, "%2x", &b) != 1)
                    break;
                mac[i] = (uint8_t)b;
            }
            if (i == HADC_MAC_LEN) {
                memcpy(l->gw_mac, mac, sizeof(mac));
                l->gw_mac_valid = true;
            }
        }
    }

    json_t *sa = json_object_get(root, "saved_at_utc");
    if (sa && json_is_integer(sa) && out->lease.address.s_addr != 0) {
        long long elapsed = (long long)time(NULL) - json_integer_value(sa);
        long long cap = 2 * (long long)out->lease.t3_remaining_s;
        if (cap > 86400)
            cap = 86400;
        if (elapsed < 0)
            hadc_warn("persist: saved_at_utc is %lld s ahead of the clock (jump); keeping "
                      "the stored timers",
                      -elapsed);
        else if (elapsed > cap)
            hadc_warn("persist: downtime %lld s exceeds the %lld s sanity cap; keeping the "
                      "stored timers",
                      elapsed, cap);
        else if (elapsed > 0) {
            uint32_t *rem[3] = { &out->lease.t1_remaining_s, &out->lease.t2_remaining_s,
                                  &out->lease.t3_remaining_s };
            for (int i = 0; i < 3; i++)
                *rem[i] = (long long)*rem[i] > elapsed ? (uint32_t)((long long)*rem[i] -
                                                                    elapsed)
                                                       : 0;
            hadc_info("persist: timers recalculated from UTC (downtime %lld s)", elapsed);
        }
    }

    if (out->found)
        hadc_lease_mark_observed(&out->lease);

    json_decref(root);
    return 0;
}

/* Serialize the cluster view. Built on the calling thread so it observes a
 * consistent ctx snapshot (the main loop owns that state); only the blocking
 * file IO is offloaded to the maintenance worker. */
static char *persist_build_json(hadc_ctx_t *ctx)
{
    /* t1/t2/t3 are remaining seconds at observed_at_utc and can be stale between
     * lease events; persist a snapshot aged to now so restarts resume correctly. */
    hadc_lease_t snap = ctx->lease;
    if (snap.observed_at_utc != 0)
        hadc_lease_adjust_elapsed(&snap, (long long)time(NULL) - snap.observed_at_utc);
    snap.observed_at_utc = (long long)time(NULL);

    json_t *lj = lease_json(&snap);
    if (!lj)
        return NULL;
    json_t *o = json_pack("{s:s, s:s, s:I, s:I, s:s, s:s, s:I, s:I, s:o}", "role",
                          ctx->role == HADC_ROLE_MASTER ? "master"
                          : ctx->role == HADC_ROLE_SLAVE ? "slave"
                          : ctx->role == HADC_ROLE_PROMOTING ? "promoting"
                          : ctx->role == HADC_ROLE_DEMOTING ? "demoting"
                                                         : "unknown",
                          "master_id", ctx->conf.designated_master,
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
    char tmp[PATH_MAX];
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
