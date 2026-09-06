#include "proto-udp-a2s.h"
#include <string.h>

int
a2s_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                   struct UdpPreparedProbe *result)
{
    (void)cookie;
    (void)target;
    memcpy(result->payload, "\xff\xff\xff\xff\x54" "Source Engine Query", 25);
    result->length = 25;
    return 1;
}

static int
a2s_string(const unsigned char *data, unsigned length, unsigned *offset)
{
    unsigned start = *offset;
    while (*offset < length && *offset - start <= 255) {
        if (!data[(*offset)++]) return 1;
    }
    return 0;
}

int
a2s_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned offset = 6, i, app;
    (void)cookie;
    if (length < 6 || length > 4096 || memcmp(data, "\xff\xff\xff\xff\x49", 5)) return 0;
    for (i = 0; i < 4; i++)
        if (!a2s_string(data, length, &offset)) return 0;
    if (length - offset < 9) return 0;
    app = (unsigned)data[offset] | (unsigned)data[offset + 1] << 8;
    if (!strchr("dlp", data[offset + 5]) || !data[offset + 5] ||
        !strchr("lwmo", data[offset + 6]) || !data[offset + 6] ||
        data[offset + 7] > 1 || data[offset + 8] > 1) return 0;
    offset += 9;
    if (app == 2400) {
        if (length - offset < 3) return 0;
        offset += 3;
    }
    if (!a2s_string(data, length, &offset)) return 0;
    if (offset < length) {
        unsigned flags = data[offset++];
        if (flags & ~0xf1u) return 0;
        if (flags & 0x80) {
            if (length - offset < 2) return 0;
            offset += 2;
        }
        if (flags & 0x10) {
            if (length - offset < 8) return 0;
            offset += 8;
        }
        if (flags & 0x40) {
            if (length - offset < 2) return 0;
            offset += 2;
            if (!a2s_string(data, length, &offset)) return 0;
        }
        if (flags & 0x20 && !a2s_string(data, length, &offset)) return 0;
        if (flags & 1) {
            if (length - offset < 8) return 0;
            offset += 8;
        }
    }
    return offset == length;
}
