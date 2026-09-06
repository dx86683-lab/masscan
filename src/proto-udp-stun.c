#include "proto-udp-stun.h"
#ifdef UDP_EXTENDED_PROBES
#include "proto-udp-runtime.h"
#include <string.h>

static unsigned
stun_u16(const unsigned char *p)
{
    return (unsigned)p[0] << 8 | p[1];
}

static uint32_t
stun_fingerprint(const unsigned char *data, unsigned length)
{
    uint32_t crc = UINT32_C(0xffffffff);
    unsigned i, bit;
    for (i = 0; i < length; i++) {
        crc ^= data[i];
        for (bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0xedb88320) : 0);
    }
    return (~crc) ^ UINT32_C(0x5354554e);
}

int
stun_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                    struct UdpPreparedProbe *result)
{
    unsigned char transaction[32];
    if (!udp_probe_derive_target("stun-transaction", cookie, 3478, target, transaction)) return 0;
    memcpy(result->payload, "\x00\x01\x00\x00\x21\x12\xa4\x42", 8);
    memcpy(result->payload + 8, transaction, 12);
    result->length = 20;
    return 1;
}

int
stun_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie,
                     const struct UdpProbeTarget *target)
{
    unsigned char transaction[32];
    unsigned offset = 20, mapped = 0, saw_mapped = 0;
    if (length < 20 || length > 4096 || memcmp(data, "\x01\x01", 2) ||
        stun_u16(data + 2) != length - 20 || (length & 3) ||
        memcmp(data + 4, "\x21\x12\xa4\x42", 4) ||
        !udp_probe_derive_target("stun-transaction", cookie, 3478, target, transaction) ||
        memcmp(data + 8, transaction, 12)) return 0;
    while (offset < length) {
        unsigned type, size, padding;
        const unsigned char *value;
        if (length - offset < 4) return 0;
        type = stun_u16(data + offset);
        size = stun_u16(data + offset + 2);
        padding = (4 - (size & 3)) & 3;
        if (size > length - offset - 4 || padding > length - offset - 4 - size) return 0;
        value = data + offset + 4;
        if (type == 0x0020 && !saw_mapped) {
            saw_mapped = 1;
            if (size < 2) return 0;
            if (value[1] == 1 || value[1] == 2) {
                if (size != (value[1] == 1 ? 8u : 20u)) return 0;
                mapped = 1;
            }
        } else if (type == 0x8028) {
            uint32_t fingerprint;
            if (size != 4 || offset + 8 != length) return 0;
            fingerprint = (uint32_t)value[0] << 24 | (uint32_t)value[1] << 16 |
                (uint32_t)value[2] << 8 | value[3];
            if (fingerprint != stun_fingerprint(data, offset)) return 0;
        } else if (type == 8 || type == 0x1c) {
            /* This anonymous profile does not verify integrity credentials. */
            return 0;
        } else if (type < 0x8000 && type != 0x0020 && type != 1 && type != 6 &&
                   type != 9 && type != 10 && type != 0x14 && type != 0x15 &&
                   type != 0x1d && type != 0x1e) return 0;
        offset += 4 + size + padding;
    }
    return mapped;
}
#endif
