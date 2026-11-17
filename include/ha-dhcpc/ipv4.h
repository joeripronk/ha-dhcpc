#ifndef HA_DHCPC_IPV4_H
#define HA_DHCPC_IPV4_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

static inline uint32_t hadc_ipv4_prefix_mask_host(unsigned prefixlen)
{
    if (prefixlen == 0)
        return 0;
    if (prefixlen >= 32)
        return 0xffffffffu;
    return 0xffffffffu << (32 - prefixlen);
}

static inline struct in_addr hadc_ipv4_prefix_mask(unsigned prefixlen)
{
    struct in_addr m;
    m.s_addr = htonl(hadc_ipv4_prefix_mask_host(prefixlen));
    return m;
}

static inline struct in_addr hadc_ipv4_network(struct in_addr addr, unsigned prefixlen)
{
    struct in_addr out;
    out.s_addr = addr.s_addr & hadc_ipv4_prefix_mask(prefixlen).s_addr;
    return out;
}

static inline unsigned hadc_ipv4_mask_to_prefix(struct in_addr mask, bool *ok)
{
    uint32_t m = ntohl(mask.s_addr);
    uint32_t inv = ~m;
    bool contiguous = (inv & (inv + 1u)) == 0;
    if (ok)
        *ok = contiguous;
    return contiguous ? (unsigned)__builtin_popcount(m) : 0;
}

static inline unsigned hadc_ipv4_netmask_prefix(struct in_addr mask)
{
    bool ok = false;
    unsigned p = hadc_ipv4_mask_to_prefix(mask, &ok);
    return ok ? p : 0;
}

static inline const char *hadc_ipv4_format(struct in_addr addr, char *buf, size_t bufsz)
{
    const char *r = (buf && bufsz) ? inet_ntop(AF_INET, &addr, buf, bufsz) : NULL;
    return r ? r : "";
}

#endif /* HA_DHCPC_IPV4_H */
