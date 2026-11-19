/* Lease timer helpers and JSON serialization. Timers are absolute UTC anchors
 * so every node and a restart derive identical remaining time from the clock. */

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ha-dhcpc/lease.h"
#include "ha-dhcpc/util.h"

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

static void lease_put_addr(json_t *obj, const char *key, struct in_addr a)
{
    char buf[64];
    json_object_set_new(obj, key, json_string(inet_ntop(AF_INET, &a, buf, sizeof(buf))));
}

static void lease_get_addr(json_t *obj, const char *key, struct in_addr *out)
{
    json_t *v = json_object_get(obj, key);
    if (v && json_is_string(v))
        inet_pton(AF_INET, json_string_value(v), out);
}

json_t *hadc_lease_to_json(const hadc_lease_t *l)
{
    char hex[65];
    json_t *dns = json_array();
    if (!dns)
        return NULL;

    hadc_hex_encode(l->config_hash, sizeof(l->config_hash), hex, sizeof(hex));
    for (size_t i = 0; i < l->n_dns; i++) {
        char buf[64];
        json_array_append_new(dns, json_string(inet_ntop(AF_INET, &l->dns[i], buf, sizeof(buf))));
    }
    json_t *o = json_pack("{s:s, s:b, s:s, s:s, s:s, s:s, s:o, s:I, s:I, s:I, s:I, s:s}",
                           "state", hadc_lease_state_name(l->state), "retention_active",
                           (int)l->retention_active, "address", "", "netmask", "", "gateway", "",
                           "server_id", "", "dns", dns, "obtained_at_utc",
                           (json_int_t)l->obtained_at_utc, "t1_at_utc",
                           (json_int_t)l->t1_at_utc, "t2_at_utc",
                           (json_int_t)l->t2_at_utc, "t3_at_utc",
                           (json_int_t)l->t3_at_utc, "config_hash", hex);
    if (!o) {
        json_decref(dns);
        return NULL;
    }
    lease_put_addr(o, "address", l->address);
    lease_put_addr(o, "netmask", l->netmask);
    lease_put_addr(o, "gateway", l->gateway);
    lease_put_addr(o, "server_id", l->server_id);
    if (l->gw_mac_valid) {
        char mac[2 * HADC_MAC_LEN + 1];
        hadc_hex_encode(l->gw_mac, HADC_MAC_LEN, mac, sizeof(mac));
        json_object_set_new(o, "gw_mac", json_string(mac));
    }
    return o;
}

void hadc_lease_from_json(json_t *lj, hadc_lease_t *out)
{
    json_t *v;

    if (!lj || !json_is_object(lj) || !out)
        return;
    if ((v = json_object_get(lj, "state")) && json_is_string(v))
        out->state = hadc_lease_state_from_name(json_string_value(v));
    if ((v = json_object_get(lj, "retention_active")) && json_is_boolean(v))
        out->retention_active = json_is_true(v);
    lease_get_addr(lj, "address", &out->address);
    lease_get_addr(lj, "netmask", &out->netmask);
    lease_get_addr(lj, "gateway", &out->gateway);
    lease_get_addr(lj, "server_id", &out->server_id);
    json_t *dns = json_object_get(lj, "dns");
    if (dns && json_is_array(dns)) {
        size_t idx;
        json_t *e;
        json_array_foreach(dns, idx, e) {
            if (json_is_string(e) && out->n_dns < HADC_DNS_MAX &&
                inet_pton(AF_INET, json_string_value(e), &out->dns[out->n_dns]) == 1)
                out->n_dns++;
        }
    }
    if ((v = json_object_get(lj, "obtained_at_utc")) && json_is_integer(v))
        out->obtained_at_utc = (long long)json_integer_value(v);
    if ((v = json_object_get(lj, "t1_at_utc")) && json_is_integer(v))
        out->t1_at_utc = (long long)json_integer_value(v);
    if ((v = json_object_get(lj, "t2_at_utc")) && json_is_integer(v))
        out->t2_at_utc = (long long)json_integer_value(v);
    if ((v = json_object_get(lj, "t3_at_utc")) && json_is_integer(v))
        out->t3_at_utc = (long long)json_integer_value(v);
    if ((v = json_object_get(lj, "config_hash")) && json_is_string(v) &&
        strlen(json_string_value(v)) == 64) {
        for (size_t i = 0; i < 32; i++) {
            unsigned b;
            if (sscanf(json_string_value(v) + 2 * i, "%2x", &b) != 1)
                break;
            out->config_hash[i] = (uint8_t)b;
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
            memcpy(out->gw_mac, mac, sizeof(mac));
            out->gw_mac_valid = true;
        }
    }
}
