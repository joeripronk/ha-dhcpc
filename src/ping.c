/* Gateway-reachability probe (layer-3 liveness): after a promote the master
 * pings the lease's gateway on a configured interval/timeout, so a silent
 * uplink failure is visible in the log and can move the default route to
 * apply.master_backup_gateway while the gateway stays silent. Kernel ping
 * sockets (SOCK_DGRAM/ICMP) are tried first, falling back to a raw ICMP socket
 * when unavailable. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ha-dhcpc/cluster.h"
#include "ha-dhcpc/dhcpcore.h"
#include "ha-dhcpc/executor.h"
#include "ha-dhcpc/ipv4.h"
#include "ha-dhcpc/log.h"
#include "ha-dhcpc/persist.h"
#include "ha-dhcpc/routing.h"
#include "internal.h"

/* magic + pid + per-probe seq + padding, so stray echo replies cannot be
 * mistaken for ours (raw sockets also see other processes' ICMP traffic).
 * The total echo packet is the standard 64 bytes: some CPE/DSLAM gear simply
 * does not answer smaller echoes. */
#define GWPING_PAYLOAD 56

static const char g_token[16] = "ha-dhcpc-gwping";
static int g_fd = -1;
static bool g_raw;          /* kernel ping socket unavailable; raw ICMP */
static bool g_awaiting;     /* probe in flight */
static bool g_unreachable;  /* failover verdict: threshold misses reached */
static bool g_unreachable_logged; /* the failover warn went out; repeats are debug */

static bool g_probe_logged; /* first success reported at info level */
static unsigned g_failures; /* consecutive unanswered probes */
static uint32_t g_seq;
static uint64_t g_last_send_ms;
static uint64_t g_unreachable_since_ms;
static uint64_t g_last_discover_ms;
static uint32_t g_interval_ms = 10000;
static uint32_t g_timeout_ms = 2000;
static unsigned g_fail_threshold = 3;

static uint16_t icmp_checksum(const void *data, size_t len)
{
    const uint8_t *p = data;
    uint32_t sum = 0;

    for (size_t i = 0; i < len - 1; i += 2)
        sum += (uint32_t)(p[i] << 8) + p[i + 1];
    if (len & 1)
        sum += (uint32_t)p[len - 1] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* The probe verdict drives the master default-route failover
 * (apply.master_backup_gateway), so a verdict change is acted on at once
 * instead of waiting for the next lease, role or reload event. */
static void reroute(hadc_ctx_t *ctx, const char *reason)
{
    hadc_desired_t desired;

    hadc_routing_reconcile(ctx, reason);
    hadc_executor_desired(ctx, &ctx->lease, &desired);
    hadc_executor_apply(ctx, &desired, reason);
}

static void validate_retained_lease(hadc_ctx_t *ctx)
{
    hadc_desired_t desired;

    if (!ctx->lease.retention_active || ctx->role != HADC_ROLE_MASTER ||
        ctx->lease.state != HADC_LEASE_RETAINED || ctx->lease.address.s_addr == 0)
        return;

    hadc_info("gwping: gateway validated; promoting retained lease to BOUND");
    hadc_cluster_lock();
    ctx->lease.retention_active = false;
    ctx->lease.state = HADC_LEASE_BOUND;
    hadc_cluster_unlock();
    hadc_executor_desired(ctx, &ctx->lease, &desired);
    hadc_executor_apply(ctx, &desired, "RETAINED-EXIT");
    hadc_routing_reconcile(ctx, "gwping-validated");
    ctx->acked_version = ctx->lease.version;
    hadc_cluster_push_state(ctx, &ctx->lease);
    hadc_persist_save(ctx);
}

static void ping_ready(hadc_ctx_t *ctx, int fd)
{
    uint8_t buf[1024];

    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                hadc_dbg("gwping: recv error %s", strerror(errno));
            break;
        }
        size_t off = 0;
        if (g_raw) {
            if ((size_t)n < sizeof(struct iphdr))
                continue;
            if (buf[9] != IPPROTO_ICMP)
                continue;
            off = (size_t)((struct iphdr *)buf)->ihl * 4;
            if (off < sizeof(struct iphdr))
                continue;
        }
        if ((size_t)n < off + sizeof(struct icmphdr) + GWPING_PAYLOAD)
            continue;
        const struct icmphdr *icmp = (const struct icmphdr *)(buf + off);
        const uint8_t *payload = buf + off + sizeof(*icmp);
        if (icmp->type != ICMP_ECHOREPLY)
            continue;
        /* Offsets below refer to payload: [0..15] magic, [16..19] pid,
         * [20..23] probe seq. */
        if (memcmp(payload, g_token, sizeof(g_token)) != 0)
            continue;
        uint32_t pid_net, seq;
        memcpy(&pid_net, payload + sizeof(g_token), sizeof(pid_net));
        memcpy(&seq, payload + sizeof(g_token) + 4, sizeof(seq));
        if (pid_net != (uint32_t)getpid() || seq != g_seq || !g_awaiting)
            continue; /* stale or foreign reply */
        g_awaiting = false;
        g_failures = 0;
        uint64_t rtt = (uint64_t)hadc_now_ms() - g_last_send_ms;
        if (g_unreachable) {
            g_unreachable = false;
            g_unreachable_logged = false; /* next failover warns again */
            g_unreachable_since_ms = 0;
            g_last_discover_ms = 0;
            hadc_info("gwping: gateway reachable again (rtt %llums)",
                      (long long)rtt);
            reroute(ctx, "GWPING-OK");
        } else if (!g_probe_logged) {
            g_probe_logged = true;
            hadc_info("gwping: gateway reachable (rtt %llums)", (long long)rtt);
        } else {
            hadc_dbg("gwping: gateway echo ok (rtt %llums)", (long long)rtt);
        }
        validate_retained_lease(ctx);
    }
}

static void send_probe(hadc_ctx_t *ctx, uint64_t now)
{
    uint8_t buf[sizeof(struct icmphdr) + GWPING_PAYLOAD];
    struct icmphdr *icmp = (struct icmphdr *)buf;
    struct sockaddr_in to = { .sin_family = AF_INET, .sin_addr = ctx->lease.gateway };
    uint32_t pid = (uint32_t)getpid(), seq = ++g_seq;

    memset(buf, 0, sizeof(buf));
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons((uint16_t)pid);
    icmp->un.echo.sequence = htons((uint16_t)(seq & 0xffff));
    memcpy(buf + sizeof(*icmp), g_token, sizeof(g_token));
    memcpy(buf + sizeof(*icmp) + sizeof(g_token), &pid, sizeof(pid));
    memcpy(buf + sizeof(*icmp) + sizeof(g_token) + 4, &seq, sizeof(seq));
    if (g_raw)
        icmp->checksum = htons(icmp_checksum(buf, sizeof(buf)));
    if (sendto(g_fd, buf, sizeof(buf), MSG_DONTWAIT,
               (struct sockaddr *)&to, sizeof(to)) < 0) {
        char gwbuf[INET_ADDRSTRLEN];
        hadc_warn("gwping: probe to %s failed: %s", hadc_ipv4_format(to.sin_addr, gwbuf, sizeof(gwbuf)),
                  strerror(errno));
        return;
    }
    g_last_send_ms = now;
    g_awaiting = true;
    { char gwbuf[INET_ADDRSTRLEN]; hadc_dbg("gwping: echo sent to %s (seq %u)", hadc_ipv4_format(to.sin_addr, gwbuf, sizeof(gwbuf)), seq); }
}

void hadc_gwping_start(hadc_ctx_t *ctx)
{
    if (g_fd >= 0)
        return;
    if (!ctx->conf.apply.gateway_probe)
        return;
    if (ctx->gwping_start_after_ms && (uint64_t)hadc_now_ms() < ctx->gwping_start_after_ms)
        return; /* delayed to avoid probe traffic/mac flips during handoff */
    g_interval_ms = ctx->conf.apply.gateway_probe_interval_ms;
    g_timeout_ms = ctx->conf.apply.gateway_probe_timeout_ms;
    g_fail_threshold = ctx->conf.apply.gateway_probe_fail_threshold;
    if (g_interval_ms == 0 || g_timeout_ms == 0 || g_fail_threshold == 0)
        return;
    g_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
    if (g_fd >= 0) {
        /* The kernel demuxes echo replies by the socket's bound ident, so a
           datagram ping socket has to be bound to the id we send with. */
        struct sockaddr_in sa = { .sin_family = AF_INET,
                                  .sin_port = htons((uint16_t)getpid()),
                                  .sin_addr.s_addr = INADDR_ANY };
        g_raw = false;
        if (bind(g_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            close(g_fd);
            g_fd = -1;
        }
    }
    if (g_fd < 0) {
        g_fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMP);
        g_raw = true;
    }
    if (g_fd < 0) {
        hadc_warn("gwping: ICMP socket failed: %s (probe skipped)",
                  strerror(errno));
        return;
    }
    if (hadc_loop_add(ctx, g_fd, ping_ready, 0) != 0) {
        hadc_warn("gwping: probe fd could not be registered; skipped");
        close(g_fd);
        g_fd = -1;
        return;
    }
    /* Always probe over the local route to the gateway: the socket follows the
       default route otherwise, and once the failover moves that default to the
       backup router, the probe would measure the backup path instead of the
       gateway. */
    if (setsockopt(g_fd, SOL_SOCKET, SO_BINDTODEVICE, ctx->conf.interface,
                   strlen(ctx->conf.interface) + 1) < 0)
        hadc_warn("gwping: could not bind the probe to %s: %s", ctx->conf.interface,
                  strerror(errno));
    g_awaiting = false;
    g_unreachable = false;
    g_unreachable_logged = false;
    g_probe_logged = false;
    g_failures = 0;
    g_last_send_ms = 0; /* the next tick sends the first probe at once */
    hadc_info("gwping: gateway probe active (every %ums, timeout %ums, failover after %u failures)",
              g_interval_ms, g_timeout_ms, g_fail_threshold);
}

void hadc_gwping_stop(hadc_ctx_t *ctx)
{
    if (g_fd < 0)
        return;
    hadc_dbg("gwping: gateway probe stopped");
    hadc_loop_del(ctx, g_fd);
    close(g_fd);
    g_fd = -1;
    g_awaiting = false;
    g_unreachable = false;      /* no probe running, so no verdict */
    g_unreachable_logged = false;
    g_probe_logged = false;
    g_failures = 0;
    g_unreachable_since_ms = 0;
    g_last_discover_ms = 0;
}

void hadc_gwping_tick(hadc_ctx_t *ctx)
{
    if (ctx->role != HADC_ROLE_MASTER) {
        ctx->gwping_start_after_ms = 0;
        if (g_fd >= 0)
            hadc_gwping_stop(ctx);
        return;
    }
    if (g_fd < 0) {
        if (ctx->gwping_start_after_ms && (uint64_t)hadc_now_ms() >= ctx->gwping_start_after_ms) {
            uint64_t due = ctx->gwping_start_after_ms;
            ctx->gwping_start_after_ms = 0;
            hadc_gwping_start(ctx);
            if (due)
                hadc_info("gwping: delayed probe start reached");
        }
        return;
    }
    uint64_t now = (uint64_t)hadc_now_ms();
    if (g_awaiting && now - g_last_send_ms >= g_timeout_ms) {
        g_awaiting = false;
        g_failures++;
        if (g_failures >= g_fail_threshold) {
            if (!g_unreachable_logged) {
                char gwbuf[INET_ADDRSTRLEN];
                g_unreachable = true;
                g_unreachable_logged = true;
                g_unreachable_since_ms = now;
                hadc_warn("gwping: gateway %s unreachable (%u consecutive probes without reply, timeout %ums); forcing DHCP renew",
                          hadc_ipv4_format((struct in_addr){ .s_addr = ctx->lease.gateway.s_addr }, gwbuf, sizeof(gwbuf)),
                          g_failures, g_timeout_ms);
                reroute(ctx, "GWPING-FAIL");
                hadc_dhcpcore_force_renew(ctx);
            } else {
                g_unreachable = true;
                hadc_dbg("gwping: gateway unreachable (repeated; probes continue)");
                if (g_unreachable_since_ms == 0)
                    g_unreachable_since_ms = now;
                /* Unicast renew can stay stuck on a dead path; escalate to
                 * DISCOVER while the gateway remains unreachable. */
                if (now - g_unreachable_since_ms >= 120000 &&
                    now - g_last_discover_ms >= 120000) {
                    hadc_warn("gwping: gateway still unreachable; forcing DHCP discover recovery");
                    if (hadc_dhcpcore_force_discover(ctx) == 0)
                        g_last_discover_ms = now;
                    else
                        hadc_dhcpcore_force_renew(ctx);
                }
            }
        }
    }
    if (ctx->lease.gateway.s_addr && !g_awaiting &&
        now - g_last_send_ms >= g_interval_ms)
        send_probe(ctx, now);
}

bool hadc_gwping_unreachable(void)
{
    return g_unreachable;
}
