/* Lease timer helpers. Remaining seconds are only trustworthy relative to the
 * moment they were last observed; promotions must age them before arming. */
#define _GNU_SOURCE

#include <limits.h>
#include <stdint.h>
#include <time.h>

#include "ha-dhcpc/lease.h"

void hadc_lease_adjust_elapsed(hadc_lease_t *l, long long elapsed_s)
{
    long long cap = 2 * (long long)l->t3_remaining_s;
    uint32_t *rem[3] = { &l->t1_remaining_s, &l->t2_remaining_s, &l->t3_remaining_s };

    if (cap > 86400)
        cap = 86400;
    if (elapsed_s < 0 || elapsed_s > cap)
        return;

    for (int i = 0; i < 3; i++) {
        if ((long long)*rem[i] > elapsed_s)
            *rem[i] = (uint32_t)((long long)*rem[i] - elapsed_s);
        else
            *rem[i] = 0;
    }
}

void hadc_lease_mark_observed(hadc_lease_t *l)
{
    l->observed_at_utc = (long long)time(NULL);
}

void hadc_lease_prepare_for_promotion(hadc_lease_t *l)
{
    if (l->observed_at_utc != 0) {
        long long elapsed = (long long)time(NULL) - l->observed_at_utc;
        hadc_lease_adjust_elapsed(l, elapsed);
    }
    hadc_lease_mark_observed(l);
}
