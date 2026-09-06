#include "proto-udp-knx.h"
#include <string.h>

int
knx_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                    struct UdpPreparedProbe *result)
{
    (void)cookie;
    (void)target;
    memcpy(result->payload, "\x06\x10\x02\x0b\x00\x12\x08\x01\x00\x00\x00\x00\x00\x00\x04\x84\x02\x01", 18);
    result->length = 18;
    return 1;
}

int
knx_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned offset = 14;
    unsigned char seen[256] = {0};
    (void)cookie;
    if (length < 14 || length > 4096 || memcmp(data, "\x06\x10\x02\x0c", 4) ||
        ((unsigned)data[4] << 8 | data[5]) != length || data[6] != 8 || data[7] != 1 ||
        ((!data[8] && !data[9] && !data[10] && !data[11]) && (data[12] || data[13]))) return 0;
    while (offset < length) {
        unsigned size, type;
        const unsigned char *block = data + offset;
        if (length - offset < 2) return 0;
        size = block[0]; type = block[1];
        if (size < 2 || size > length - offset || seen[type]) return 0;
        seen[type] = 1;
        if (type == 1) {
            if (size != 54 || (block[2] != 2 && block[2] != 4 && block[2] != 16 && block[2] != 32)) return 0;
            if ((block[14] || block[15] || block[16] || block[17]) && (block[14] & 0xf0) != 0xe0) return 0;
        } else if (type == 2 || type == 6) {
            unsigned i;
            unsigned char families[256] = {0};
            if (size < (type == 2 ? 4u : 2u) || size % 2) return 0;
            for (i = 2; i < size; i += 2) {
                if (families[block[i]]) return 0;
                families[block[i]] = 1;
            }
        } else if (type == 3) {
            if (size != 16) return 0;
        } else if (type == 4) {
            if (size != 20) return 0;
        } else if (type == 5) {
            if (size < 4 || size % 2) return 0;
        } else if (type == 7) {
            if (size < 8 || size % 4) return 0;
        } else if (type == 8) {
            if (size != 8) return 0;
        } else if (type == 254) {
            if (size < 4) return 0;
        }
        offset += size;
    }
    return seen[1] && seen[2];
}
