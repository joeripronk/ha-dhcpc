/* Minimal SHA-256 (FIPS 180-4) for config hashing. */
#include <stdint.h>
#include <string.h>

#include "internal.h"

typedef struct {
    uint32_t h[8];
} sha256_t;

static const uint32_t KK[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define ror32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_compress(sha256_t *s, const uint8_t blk[64])
{
    uint32_t w[64], a, b, c, d, e, f, g, h;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16) |
               ((uint32_t)blk[i * 4 + 2] << 8) | blk[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
    e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + KK[i] + w[i];
        uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

void hadc_sha256(const void *data, size_t len, uint8_t out[32])
{
    static const uint32_t H0[8] = { 0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u };
    sha256_t s;
    memcpy(s.h, H0, sizeof(H0));

    const uint8_t *p = data;
    size_t n = len;
    while (n >= 64) {
        sha256_compress(&s, p);
        p += 64;
        n -= 64;
    }

    uint64_t bits = (uint64_t)len * 8;
    uint8_t blk[128];
    memcpy(blk, p, n);
    blk[n] = 0x80;
    if (n + 1 + 8 <= 64) {
        memset(blk + n + 1, 0, 55 - n);
    } else {
        memset(blk + n + 1, 0, 63 - n);
        sha256_compress(&s, blk);
        memset(blk, 0, 56);
    }
    for (int i = 0; i < 8; i++)
        blk[56 + i] = (uint8_t)(bits >> (56 - i * 8));
    sha256_compress(&s, blk);

    for (int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(s.h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(s.h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(s.h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)s.h[i];
    }
}
