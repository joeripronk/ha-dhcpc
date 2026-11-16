/* Lease timer promotion tests: remaining seconds must age before the DHCP
 * core arms its timers on a promoted slave. */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "ha-dhcpc/lease.h"

static int fail(const char *what)
{
    printf("lease_test: FAIL (%s)\n", what);
    return 1;
}

int main(void)
{
    hadc_lease_t l = { 0 };
    time_t before, after;
    long long elapsed;

    l.t1_remaining_s = 900;
    l.t2_remaining_s = 1566;
    l.t3_remaining_s = 1800;
    l.observed_at_utc = (long long)time(NULL) - 700;
    before = time(NULL);
    hadc_lease_prepare_for_promotion(&l);
    after = time(NULL);
    elapsed = (long long)after - ((long long)after - 700);

    if (l.t1_remaining_s != (uint32_t)(900 - elapsed) ||
        l.t2_remaining_s != (uint32_t)(1566 - elapsed) ||
        l.t3_remaining_s != (uint32_t)(1800 - elapsed))
        return fail("promotion ages timers");
    if (l.observed_at_utc < (long long)before || l.observed_at_utc > (long long)after)
        return fail("promotion marks observed time");

    l.observed_at_utc = 0;
    l.t1_remaining_s = 900;
    l.t2_remaining_s = 1566;
    l.t3_remaining_s = 1800;
    hadc_lease_adjust_elapsed(&l, 100);
    if (l.t1_remaining_s != 800 || l.t2_remaining_s != 1466 || l.t3_remaining_s != 1700)
        return fail("adjust elapsed");

    hadc_lease_adjust_elapsed(&l, -1);
    if (l.t1_remaining_s != 800 || l.t2_remaining_s != 1466 || l.t3_remaining_s != 1700)
        return fail("negative elapsed keeps timers");

    l.t1_remaining_s = 900;
    l.t2_remaining_s = 1566;
    l.t3_remaining_s = 100;
    hadc_lease_adjust_elapsed(&l, 201);
    if (l.t1_remaining_s != 900 || l.t2_remaining_s != 1566 || l.t3_remaining_s != 100)
        return fail("over cap keeps timers");

    l.t1_remaining_s = 100;
    l.t2_remaining_s = 200;
    l.t3_remaining_s = 300;
    hadc_lease_adjust_elapsed(&l, 250);
    if (l.t1_remaining_s != 0 || l.t2_remaining_s != 0 || l.t3_remaining_s != 50)
        return fail("clamps expired timers");

    /* Promotion delay applies to an existing T1 even without T2 (no accel). */
    l.observed_at_utc = 0;
    inet_pton(AF_INET, "10.0.0.1", &l.address);
    l.state = HADC_LEASE_BOUND;
    l.t1_remaining_s = 300;
    l.t2_remaining_s = 0;
    l.t3_remaining_s = 600;
    hadc_lease_prepare_for_promotion(&l);
    if (l.t1_remaining_s != 305)
        return fail("existing T1 is delayed, never accelerated, when T2 is absent");

    /* T1=0 with no T3: nothing to delay, must not collapse to immediate. */
    l.t1_remaining_s = 0;
    l.t2_remaining_s = 0;
    l.t3_remaining_s = 0;
    hadc_lease_prepare_for_promotion(&l);
    if (l.t1_remaining_s != 0)
        return fail("no timers: nothing to delay");

    /* T1=0, T2=0, T3=600: delay seeds T1 at min(5, T3). */
    l.t1_remaining_s = 0;
    l.t2_remaining_s = 0;
    l.t3_remaining_s = 600;
    hadc_lease_prepare_for_promotion(&l);
    if (l.t1_remaining_s != 5)
        return fail("T1 seed from T3 when T1/T2 absent");

    /* T1 > T3 with T3=0 must not clamp T1 to zero (delay still applies). */
    l.t1_remaining_s = 100;
    l.t2_remaining_s = 0;
    l.t3_remaining_s = 0;
    hadc_lease_prepare_for_promotion(&l);
    if (l.t1_remaining_s != 105)
        return fail("T1 must not collapse when T3 absent");

    printf("lease_test: OK\n");
    return 0;
}
