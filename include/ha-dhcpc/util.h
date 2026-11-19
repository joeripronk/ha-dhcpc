#ifndef HA_DHCPC_UTIL_H
#define HA_DHCPC_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Encode n bytes as lowercase hex. out needs 2*n+1 bytes; output is always
 * NUL-terminated and truncated safely if outsz is too small. */
static inline void hadc_hex_encode(const uint8_t *in, size_t n, char *out, size_t outsz)
{
    static const char digits[] = "0123456789abcdef";

    if (outsz == 0)
        return;
    size_t k = 0;
    for (size_t i = 0; i < n && k + 2 < outsz; i++) {
        out[k++] = digits[in[i] >> 4];
        out[k++] = digits[in[i] & 0x0f];
    }
    out[k] = '\0';
}

/* RFC 1071 one's-complement checksum. net_order sums 16-bit words read in
 * network (big-endian) byte order; otherwise words are read in host order. */
static inline uint16_t hadc_checksum_ex(const void *data, size_t len, bool net_order)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;

    if (net_order) {
        for (size_t i = 0; i + 1 < len; i += 2)
            sum += ((uint32_t)p[i] << 8) | p[i + 1];
        if (len & 1)
            sum += (uint32_t)p[len - 1] << 8;
    } else {
        for (size_t i = 0; i + 1 < len; i += 2) {
            uint16_t word;
            memcpy(&word, p + i, sizeof(word));
            sum += word;
        }
        if (len & 1)
            sum += p[len - 1];
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static inline uint16_t hadc_checksum_net(const void *data, size_t len)
{
    return hadc_checksum_ex(data, len, true);
}

static inline uint16_t hadc_checksum_host(const void *data, size_t len)
{
    return hadc_checksum_ex(data, len, false);
}

#endif /* HA_DHCPC_UTIL_H */
