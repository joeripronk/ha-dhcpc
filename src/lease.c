/* Lease timer helpers. Timers are absolute UTC anchors so every node and a
 * restart derive identical remaining time from the clock (no snapshot aging). */
#define _GNU_SOURCE

#include <stdint.h>
#include <time.h>

#include "ha-dhcpc/lease.h"

uint32_t hadc_lease_remaining_one(long long at_utc, long long now_utc)
{
    if (at_utc <= 0)
        return 0;
    if (now_utc >= at_utc)
        return 0;
    long long d = at_utc - now_utc;
    if (d > (long long)UINT32_MAX)
        return UINT32_MAX;
    return (uint32_t)d;
}

void hadc_lease_remaining(const hadc_lease_t *l, long long now_utc,
                          uint32_t *t1, uint32_t *t2, uint32_t *t3)
{
    if (t1)
        *t1 = hadc_lease_remaining_one(l->t1_at_utc, now_utc);
    if (t2)
        *t2 = hadc_lease_remaining_one(l->t2_at_utc, now_utc);
    if (t3)
        *t3 = hadc_lease_remaining_one(l->t3_at_utc, now_utc);
}

void hadc_lease_prepare_for_promotion(hadc_lease_t *l)
{
    /* Delay renew on the new master by 5 seconds (avoid churn/flaps during
     * promotion handoff), clamped so T1 <= T2 <= T3, without accelerating or
     * making an expired/unknown timer active. */
    if (l->address.s_addr == 0 || l->state == HADC_LEASE_NONE)
        return;
    const long long delay_s = 5;
    long long now = (long long)time(NULL);

    if (l->t1_at_utc > now)
        l->t1_at_utc += delay_s;
    else if (l->t2_at_utc > now)
        l->t1_at_utc = (l->t2_at_utc - now > delay_s) ? now + delay_s : l->t2_at_utc;
    else if (l->t3_at_utc > now)
        l->t1_at_utc = (l->t3_at_utc - now > delay_s) ? now + delay_s : l->t3_at_utc;
    else
        return;

    if (l->t2_at_utc > 0 && l->t1_at_utc > l->t2_at_utc)
        l->t1_at_utc = l->t2_at_utc;
    if (l->t3_at_utc > 0 && l->t2_at_utc > 0 && l->t2_at_utc > l->t3_at_utc)
        l->t2_at_utc = l->t3_at_utc;
    if (l->t3_at_utc > 0 && l->t1_at_utc > l->t3_at_utc)
        l->t1_at_utc = l->t3_at_utc;
}
