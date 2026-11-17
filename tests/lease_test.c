#define _GNU_SOURCE

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
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
    long long now = (long long)time(NULL);
    uint32_t t1, t2, t3;

    l.obtained_at_utc = now - 700;
    l.t1_at_utc = now + 200;
    l.t2_at_utc = now + 866;
    l.t3_at_utc = now + 1100;
    hadc_lease_remaining(&l, now, &t1, &t2, &t3);
    if (t1 != 200 || t2 != 866 || t3 != 1100)
        return fail("remaining from anchors");

    hadc_lease_remaining(&l, now + 250, &t1, &t2, &t3);
    if (t1 != 0 || t2 != 616 || t3 != 850)
        return fail("remaining clamps/advances");

    /* Promotion delay applies to an existing future T1. */
    memset(&l, 0, sizeof(l));
    inet_pton(AF_INET, "10.0.0.1", &l.address);
    l.state = HADC_LEASE_BOUND;
    l.obtained_at_utc = now;
    l.t1_at_utc = now + 300;
    l.t2_at_utc = 0;
    l.t3_at_utc = now + 600;
    hadc_lease_prepare_for_promotion(&l);
    hadc_lease_remaining(&l, now, &t1, &t2, &t3);
    if (t1 != 305)
        return fail("existing T1 is delayed, never accelerated, when T2 is absent");

    /* T1 expired, no T2/T3: nothing to delay. */
    memset(&l, 0, sizeof(l));
    inet_pton(AF_INET, "10.0.0.1", &l.address);
    l.state = HADC_LEASE_BOUND;
    l.obtained_at_utc = now - 10;
    l.t1_at_utc = 0;
    l.t2_at_utc = 0;
    l.t3_at_utc = 0;
    hadc_lease_prepare_for_promotion(&l);
    if (hadc_lease_remaining_one(l.t1_at_utc, now) != 0)
        return fail("no timers: nothing to delay");

    /* T1=0, T2=0, T3 future: delay seeds T1 at min(5, T3). */
    memset(&l, 0, sizeof(l));
    inet_pton(AF_INET, "10.0.0.1", &l.address);
    l.state = HADC_LEASE_BOUND;
    l.obtained_at_utc = now;
    l.t1_at_utc = 0;
    l.t2_at_utc = 0;
    l.t3_at_utc = now + 600;
    hadc_lease_prepare_for_promotion(&l);
    hadc_lease_remaining(&l, now, &t1, &t2, &t3);
    if (t1 != 5)
        return fail("T1 seed from T3 when T1/T2 absent");

    /* T1 future > T3 expired must not collapse to zero. */
    memset(&l, 0, sizeof(l));
    inet_pton(AF_INET, "10.0.0.1", &l.address);
    l.state = HADC_LEASE_BOUND;
    l.obtained_at_utc = now;
    l.t1_at_utc = now + 100;
    l.t2_at_utc = 0;
    l.t3_at_utc = 0;
    hadc_lease_prepare_for_promotion(&l);
    hadc_lease_remaining(&l, now, &t1, &t2, &t3);
    if (t1 != 105)
        return fail("T1 must not collapse when T3 absent");

    printf("lease_test: OK\n");
    return 0;
}
