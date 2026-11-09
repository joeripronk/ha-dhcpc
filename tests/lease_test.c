/* Lease timer promotion tests: remaining seconds must age before the DHCP
 * core arms its timers on a promoted slave. */
#define _GNU_SOURCE

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

    printf("lease_test: OK\n");
    return 0;
}
