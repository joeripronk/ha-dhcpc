/* Round-trip test: everything needed to re-apply interface state at boot
 * must survive save -> load (plan §3/§8 cache). */
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
    a->lease.t1_remaining_s = 8000;
    a->lease.t2_remaining_s = 10000;
    a->lease.t3_remaining_s = 12000;
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
    if (pv.lease.t1_remaining_s != 8000 || pv.lease.t2_remaining_s != 10000 ||
        pv.lease.t3_remaining_s != 12000)
        rc |= fail("timers");
    if (memcmp(pv.lease.config_hash, a->lease.config_hash, 32) != 0)
        rc |= fail("config_hash");

    /* Restart recalculates remaining time from UTC (plan §8), with a sanity cap
     * min(2*t3, 24 h) on crazy jumps. */
    {
        static const struct {
            long long saved_delta; /* saved_at_utc = now + delta */
            uint32_t t1, t2, t3;   /* expected after load */
            const char *what;
        } cases[] = {
            { -300, 7700, 9700, 11700, "recalc within cap" },
            { 300, 8000, 10000, 12000, "clock jump keeps stored timers" },
            { -(long long)86401, 8000, 10000, 12000, "downtime beyond cap keeps stored timers" },
            { -(long long)24000, 0, 0, 0, "downtime past expiry clamps to zero" },
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            json_error_t jerr;
            json_t *root = json_loadf(fopen(path, "r"), 0, &jerr);
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
            if (v.lease.t1_remaining_s != cases[i].t1 || v.lease.t2_remaining_s != cases[i].t2 ||
                v.lease.t3_remaining_s != cases[i].t3)
                rc |= fail(cases[i].what);
        }
    }

    unlink(path);
    if (rc == 0)
        printf("persist_test: OK\n");
    return rc;
}
