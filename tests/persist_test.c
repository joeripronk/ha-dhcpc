#define _GNU_SOURCE

#include <arpa/inet.h>
#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ha-dhcpc/persist.h"
#include "internal.h"

static hadc_ctx_t g_a, g_b;

static int fail(const char *what)
{
    printf("persist_test: FAIL (%s)\n", what);
    return 1;
}

int main(void)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/opencode/persist_test_%d.json", (int)getpid());
    unlink(path);

    hadc_ctx_t *a = &g_a;
    long long now = (long long)time(NULL);
    a->role = HADC_ROLE_MASTER;
    a->lease.version = 7;
    a->acked_version = 5;
    snprintf(a->conf.interface, sizeof(a->conf.interface), "eth0");
    a->lease.state = HADC_LEASE_BOUND;
    a->lease.retention_active = true;
    inet_pton(AF_INET, "10.99.0.50", &a->lease.address);
    inet_pton(AF_INET, "255.255.255.0", &a->lease.netmask);
    inet_pton(AF_INET, "10.99.0.1", &a->lease.gateway);
    inet_pton(AF_INET, "10.99.0.254", &a->lease.server_id);
    inet_pton(AF_INET, "8.8.8.8", &a->lease.dns[0]);
    inet_pton(AF_INET, "1.1.1.1", &a->lease.dns[1]);
    a->lease.n_dns = 2;
    {
        static const uint8_t want_mac[HADC_MAC_LEN] = { 0x02, 0x00, 0x11, 0x22, 0x33, 0x44 };
        memcpy(a->lease.gw_mac, want_mac, HADC_MAC_LEN);
    }
    a->lease.gw_mac_valid = true;
    a->lease.obtained_at_utc = now - 100;
    a->lease.t1_at_utc = now + 8000;
    a->lease.t2_at_utc = now + 10000;
    a->lease.t3_at_utc = now + 12000;
    for (size_t i = 0; i < 32; i++)
        a->lease.config_hash[i] = (uint8_t)(i * 3);

    if (hadc_persist_init(a, path) != 0)
        return fail("init");
    if (hadc_persist_save(a) != 0)
        return fail("save");

    hadc_ctx_t *b = &g_b;
    hadc_persist_view_t pv;
    if (hadc_persist_init(b, path) != 0)
        return fail("init2");
    if (hadc_persist_load(b, &pv) != 0)
        return fail("load");

    int rc = 0;
    if (!pv.found)
        return fail("found");
    if (pv.role != HADC_ROLE_MASTER)
        rc |= fail("role");
    if (pv.lease_version != 7 || pv.acked_version != 5)
        rc |= fail("versions");
    if (pv.lease.state != HADC_LEASE_BOUND || !pv.lease.retention_active)
        rc |= fail("state/retention");
    if (memcmp(&pv.lease.address, &a->lease.address, sizeof(pv.lease.address)) != 0)
        rc |= fail("address");
    if (memcmp(&pv.lease.netmask, &a->lease.netmask, sizeof(pv.lease.netmask)) != 0)
        rc |= fail("netmask");
    if (memcmp(&pv.lease.gateway, &a->lease.gateway, sizeof(pv.lease.gateway)) != 0)
        rc |= fail("gateway");
    if (memcmp(&pv.lease.server_id, &a->lease.server_id, sizeof(pv.lease.server_id)) != 0)
        rc |= fail("server_id");
    if (pv.lease.n_dns != 2 ||
        memcmp(&pv.lease.dns, &a->lease.dns, 2 * sizeof(pv.lease.dns[0])) != 0)
        rc |= fail("dns");
    if (pv.lease.obtained_at_utc != a->lease.obtained_at_utc ||
        pv.lease.t1_at_utc != a->lease.t1_at_utc ||
        pv.lease.t2_at_utc != a->lease.t2_at_utc ||
        pv.lease.t3_at_utc != a->lease.t3_at_utc)
        rc |= fail("timer anchors");
    if (memcmp(pv.lease.config_hash, a->lease.config_hash, 32) != 0)
        rc |= fail("config_hash");
    if (!pv.lease.gw_mac_valid || memcmp(pv.lease.gw_mac, a->lease.gw_mac, HADC_MAC_LEN) != 0)
        rc |= fail("gw_mac");

    /* Restart: absolute anchors remain the source of truth (even across large
     * downtime/clock jumps of saved_at_utc); remaining is derived from now. */
    {
        static const struct { long long saved_delta; const char *what; } cases[] = {
            { -300, "recalc within cap" },
            { 300, "clock jump keeps stored anchors" },
            { -(long long)86401, "downtime beyond cap keeps stored anchors" },
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            json_error_t jerr;
            FILE *rf = fopen(path, "r");
            json_t *root = json_loadf(rf, 0, &jerr);
            if (rf) fclose(rf);
            if (!root)
                return fail("reopen");
            json_object_set_new(root, "saved_at_utc",
                                json_integer((json_int_t)time(NULL) + cases[i].saved_delta));
            FILE *f = fopen(path, "w");
            json_dumpf(root, f, 0);
            fclose(f);
            json_decref(root);
            hadc_persist_view_t v;
            if (hadc_persist_load(b, &v) != 0)
                return fail("recalc load");
            if (v.lease.t1_at_utc != a->lease.t1_at_utc || v.lease.t2_at_utc != a->lease.t2_at_utc ||
                v.lease.t3_at_utc != a->lease.t3_at_utc)
                rc |= fail(cases[i].what);
        }
    }

    /* Backward compat: legacy remaining-second snapshot is converted. */
    {
        json_error_t jerr;
        FILE *rf = fopen(path, "r");
        json_t *root = json_loadf(rf, 0, &jerr);
        if (rf) fclose(rf);
        if (!root)
            return fail("reopen legacy");
        json_t *lj = json_object_get(root, "lease");
        json_object_del(lj, "obtained_at_utc");
        json_object_del(lj, "t1_at_utc");
        json_object_del(lj, "t2_at_utc");
        json_object_del(lj, "t3_at_utc");
        long long base = (long long)time(NULL) - 10;
        json_object_set_new(lj, "observed_at_utc", json_integer(base));
        json_object_set_new(lj, "t1_remaining_s", json_integer(100));
        json_object_set_new(lj, "t2_remaining_s", json_integer(200));
        json_object_set_new(lj, "t3_remaining_s", json_integer(300));
        FILE *f = fopen(path, "w");
        json_dumpf(root, f, 0);
        fclose(f);
        json_decref(root);
        hadc_persist_view_t v;
        if (hadc_persist_load(b, &v) != 0)
            return fail("legacy load");
        if (v.lease.t1_at_utc != base + 100 || v.lease.t2_at_utc != base + 200 ||
            v.lease.t3_at_utc != base + 300)
            rc |= fail("legacy conversion");
        /* remaining derived from anchors now, not snapshotted */
        if (hadc_lease_remaining_one(v.lease.t3_at_utc, base + 50) != 250)
            rc |= fail("legacy remaining derived");
    }

    unlink(path);
    if (rc == 0)
        printf("persist_test: OK\n");
    return rc;
}
