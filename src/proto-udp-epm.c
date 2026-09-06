#include "proto-udp-epm.h"
#ifdef UDP_EXTENDED_PROBES
#include "proto-udp-runtime.h"
#include <string.h>

static const unsigned char epm_interface[16] =
    "\x08\x83\xaf\xe1\x1f\x5d\xc9\x11\x91\xa4\x08\x00\x2b\x14\xa0\xfa";
static const unsigned char pnio_interface[16] =
    "\x01\x00\xa0\xde\x97\x6c\xd1\x11\x82\x71\x00\xa0\x24\x42\xdf\x7d";
static const unsigned char ndr_interface[16] =
    "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60";

static unsigned
epm_u16(const unsigned char *p)
{
    return (unsigned)p[0] | (unsigned)p[1] << 8;
}

static uint32_t
epm_u32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int
epm_activity(uint64_t cookie, const struct UdpProbeTarget *target, unsigned char id[32])
{
    if (!udp_probe_derive_target("epm-activity", cookie, 34964, target, id)) return 0;
    id[7] = (id[7] & 15) | 0x40;
    id[8] = (id[8] & 63) | 0x80;
    return 1;
}

int
epm_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                   struct UdpPreparedProbe *result)
{
    unsigned char activity[32];
    if (!epm_activity(cookie, target, activity)) return 0;
    memset(result->payload, 0, 156);
    memcpy(result->payload, "\x04\x00\x08\x00\x10\x00\x00\x00", 8);
    memcpy(result->payload + 24, epm_interface, 16);
    memcpy(result->payload + 40, activity, 16);
    result->payload[60] = 3;
    memcpy(result->payload + 68, "\x02\x00\xff\xff\xff\xff\x4c\x00", 8);
    /* Two distinct non-null full pointers to nil values in a read-all call. */
    result->payload[86] = 2;
    result->payload[104] = 4; result->payload[106] = 2;
    result->payload[128] = 1;
    result->payload[152] = 1;
    result->length = 156;
    return 1;
}

static int
epm_tower(const unsigned char *data, unsigned length)
{
    unsigned offset = 2, floor;
    int identity = PROTO_NONE;
    if (length < 2 || epm_u16(data) != 5) return PROTO_NONE;
    for (floor = 0; floor < 5; floor++) {
        unsigned left_length, right_length;
        const unsigned char *left, *right;
        if (length - offset < 2) return PROTO_NONE;
        left_length = epm_u16(data + offset); offset += 2;
        if (left_length > length - offset) return PROTO_NONE;
        left = data + offset; offset += left_length;
        if (length - offset < 2) return PROTO_NONE;
        right_length = epm_u16(data + offset); offset += 2;
        if (right_length > length - offset) return PROTO_NONE;
        right = data + offset; offset += right_length;
        if (floor < 2) {
            if (left_length != 19 || right_length != 2 || left[0] != 13 || epm_u16(right)) return PROTO_NONE;
            if (!floor) {
                if (!memcmp(left + 1, pnio_interface, 16) && epm_u16(left + 17) == 1) identity = PROTO_PNIO;
                else if (!memcmp(left + 1, epm_interface, 16) && epm_u16(left + 17) == 3) identity = PROTO_EPM;
                else return PROTO_NONE;
            } else if (memcmp(left + 1, ndr_interface, 16) || epm_u16(left + 17) != 2) return PROTO_NONE;
        } else {
            if (left_length != 1 || left[0] != (floor == 2 ? 10 : floor == 3 ? 8 : 9) ||
                right_length != (floor == 4 ? 4u : 2u)) return PROTO_NONE;
            if (floor == 2 && epm_u16(right)) return PROTO_NONE;
            if (floor == 3 && !right[0] && !right[1]) return PROTO_NONE;
        }
    }
    return offset == length ? identity : PROTO_NONE;
}

static int
epm_result(const unsigned char *data, unsigned length)
{
    unsigned offset, annotation, tower_length;
    int identity;
    if (length < 64 || epm_u32(data + 20) != 1 || epm_u32(data + 24) != 1 ||
        epm_u32(data + 28) || epm_u32(data + 32) != 1 || !epm_u32(data + 52) || epm_u32(data + 56)) return PROTO_NONE;
    annotation = epm_u32(data + 60);
    if (!annotation || annotation > 64 || annotation > length - 64 || data[63 + annotation]) return PROTO_NONE;
    offset = (64 + annotation + 3) & ~3u;
    if (offset > length || length - offset < 8) return PROTO_NONE;
    tower_length = epm_u32(data + offset + 4);
    if (tower_length > 1024 || epm_u32(data + offset) != tower_length || tower_length > length - offset - 8) return PROTO_NONE;
    identity = epm_tower(data + offset + 8, tower_length);
    offset = (offset + 8 + tower_length + 3) & ~3u;
    if (offset > length || length - offset != 4 || epm_u32(data + offset)) return PROTO_NONE;
    return identity;
}

int
epm_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie,
                    const struct UdpProbeTarget *target)
{
    unsigned char activity[32];
    if (length < 80 || length > 4096 || data[0] != 4 || data[1] != 2 ||
        (data[2] & ~0x28u) || data[3] || memcmp(data + 4, "\x10\x00\x00", 3) ||
        epm_u32(data + 64) || epm_u16(data + 74) != length - 80 || epm_u16(data + 76) || data[78] ||
        !epm_activity(cookie, target, activity) || memcmp(data + 40, activity, 16)) return PROTO_NONE;
    return epm_result(data + 80, length - 80);
}
#endif
