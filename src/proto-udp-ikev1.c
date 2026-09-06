#include "proto-udp-ikev1.h"
#ifdef UDP_EXTENDED_PROBES
#include "proto-udp-runtime.h"
#include <string.h>

static unsigned
ikev1_u16(const unsigned char *p)
{
    return (unsigned)p[0] << 8 | p[1];
}

static uint32_t
ikev1_u32(const unsigned char *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

int
ikev1_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                     struct UdpPreparedProbe *result)
{
    static const unsigned char offer[] =
        "\x0d\x00\x00\x30\x00\x00\x00\x01\x00\x00\x00\x01"
        "\x00\x00\x00\x24\x01\x01\x00\x01"
        "\x00\x00\x00\x1c\x01\x01\x00\x00"
        "\x80\x01\x00\x07\x80\x02\x00\x02\x80\x03\x00\x03"
        "\x80\x04\x00\x0e\x80\x0e\x00\x80"
        "\x00\x00\x00\x14\x4a\x13\x1c\x81\x07\x03\x58\x45"
        "\x5c\x57\x28\xf2\x0e\x95\x45\x2f";
    unsigned char random[32];
    unsigned i, nonzero = 0;
    (void)target;
    if (!udp_probe_derive("ikev1-cookie", cookie, random)) return 0;
    for (i = 0; i < 8; i++) nonzero |= random[i];
    if (!nonzero) return 0;
    memset(result->payload, 0, 32);
    memcpy(result->payload + 4, random, 8);
    memcpy(result->payload + 20, "\x01\x10\x02", 3);
    result->payload[31] = 96;
    memcpy(result->payload + 32, offer, sizeof(offer) - 1);
    result->length = 100;
    return 1;
}

static int
ikev1_sa(const unsigned char *data, unsigned length)
{
    unsigned offset = 28, seen = 0;
    if (length < 28 || ikev1_u32(data + 4) != 1 || ikev1_u32(data + 8) != 1 ||
        data[12] || ikev1_u16(data + 14) != length - 12 || data[16] != 1 ||
        data[17] != 1 || data[18] || data[19] != 1 || data[20] ||
        ikev1_u16(data + 22) != length - 20 || data[24] != 1 || data[25] != 1) return 0;
    while (offset < length) {
        unsigned type, value, expected;
        if (length - offset < 4) return 0;
        type = ikev1_u16(data + offset);
        value = ikev1_u16(data + offset + 2);
        /* All five offered attributes have the RFC basic representation. */
        if (!(type & 0x8000)) return 0;
        type &= 0x7fff;
        switch (type) {
        case 1: expected = 7; break;
        case 2: expected = 2; break;
        case 3: expected = 3; break;
        case 4: expected = 14; break;
        case 14: expected = 128; break;
        default: return 0;
        }
        if (value != expected || (seen & (1u << type))) return 0;
        seen |= 1u << type;
        offset += 4;
    }
    return seen == 0x401e;
}

int
ikev1_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned char random[32];
    unsigned offset = 32, next, saw_sa = 0, i, nonzero = 0;
    if (length < 32 || length > 4096 || ikev1_u32(data) ||
        data[20] != 1 || data[21] != 0x10 || data[22] != 2 || (data[23] & 7) ||
        ikev1_u32(data + 24) || ikev1_u32(data + 28) != length - 4 ||
        !udp_probe_derive("ikev1-cookie", cookie, random) || memcmp(data + 4, random, 8)) return 0;
    for (i = 12; i < 20; i++) nonzero |= data[i];
    if (!nonzero) return 0;
    next = data[20];
    while (next) {
        unsigned size;
        if (length - offset < 4) return 0;
        size = ikev1_u16(data + offset + 2);
        if (size < 4 || size > length - offset) return 0;
        if (next == 1) {
            if (saw_sa || !ikev1_sa(data + offset, size)) return 0;
            saw_sa = 1;
        } else if (next == 13) {
            if (size < 5) return 0;
        } else return 0;
        next = data[offset];
        offset += size;
    }
    return saw_sa && offset == length;
}
#endif
