/* Executor: declarative desired state + idempotent netlink reconcile (plan §3).
 * M1 scaffold: desired-state computation + hashing implemented; netlink
 * reconcile and dhclient-script dispatch are M1/M2 work (logged as stubs). */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <jansson.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/addr.h>
#include <netlink/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/log.h"
#include "internal.h"

static struct nl_sock *g_sk;

int hadc_executor_init(hadc_ctx_t *ctx)
{
    g_sk = nl_socket_alloc();
    if (!g_sk) {
        hadc_err("executor: nl_socket_alloc failed");
        return -1;
    }
    if (nl_connect(g_sk, NETLINK_ROUTE) != 0) {
        hadc_err("executor: netlink connect failed");
        nl_socket_free(g_sk);
        g_sk = NULL;
        return -1;
    }
    nl_socket_free(g_sk); /* M1: keep socket open for reconcile */
    g_sk = NULL;
    hadc_info("executor: netlink reachable (idempotent reconcile lands in M1)");
    (void)ctx;
    return 0;
}

/* Canonical desired-state text for hashing: stable field order. */
static void canonical_desired(const hadc_desired_t *d, char *out, size_t outsz)
{
    json_t *o = json_pack(
        "{s:s, s:b, s:s, s:I, s:s, s:s, s:s}", "interface", d->interface, "present", d->present,
        "address", inet_ntoa(d->address), "prefixlen", (json_int_t)d->prefixlen, "gateway",
        inet_ntoa(d->gateway), "dns", "", "routes", d->add_routes ? "yes" : "no");
    json_t *dns = json_array();
    for (size_t i = 0; i < d->n_dns; i++)
        json_array_append_new(dns, json_string(inet_ntoa(d->dns[i])));
    json_object_set_new(o, "dns", dns);
    char *txt = json_dumps(o, JSON_PRESERVE_ORDER | JSON_COMPACT);
    snprintf(out, outsz, "%s", txt ? txt : "");
    free(txt);
    json_decref(o);
}

void hadc_executor_desired(hadc_ctx_t *ctx, const hadc_lease_t *lease, hadc_desired_t *out)
{
    memset(out, 0, sizeof(*out));
    snprintf(out->interface, sizeof(out->interface), "%s", ctx->conf.interface);
    out->add_routes = ctx->conf.apply.routes;

    if (lease->state == HADC_LEASE_NONE) {
        out->present = false;
    } else {
        out->present = true;
        out->address = lease->address;
        out->prefixlen = 32 - (unsigned)__builtin_clz(
            ntohl(lease->netmask.s_addr) ? ntohl(lease->netmask.s_addr) : 0);
        out->gateway = lease->gateway;
        out->n_dns = lease->n_dns;
        for (size_t i = 0; i < lease->n_dns; i++)
            out->dns[i] = lease->dns[i];
    }
    char canon[1024];
    canonical_desired(out, canon, sizeof(canon));
    hadc_sha256(canon, strlen(canon), out->config_hash);
}

static hadc_hash_t g_applied_hash;
static bool g_applied_valid;

int hadc_executor_apply(hadc_ctx_t *ctx, const hadc_desired_t *desired, const char *reason)
{
    if (g_applied_valid && !memcmp(g_applied_hash, desired->config_hash, sizeof(g_applied_hash))) {
        hadc_dbg("executor: desired state already applied (no delta, reason=%s)", reason);
        return 0;
    }
    memcpy(g_applied_hash, desired->config_hash, sizeof(g_applied_hash));
    g_applied_valid = true;
    hadc_info("executor: apply delta reason=%s interface=%s present=%d hash=%02x%02x%02x%02x "
              "(netlink reconcile + hook dispatch land in M1)",
              reason, desired->interface, desired->present, desired->config_hash[0],
              desired->config_hash[1], desired->config_hash[2], desired->config_hash[3]);
    (void)ctx;
    return 0;
}
