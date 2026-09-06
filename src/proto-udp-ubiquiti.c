#include "proto-udp-ubiquiti.h"
#include <string.h>

int
ubiquiti_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                        struct UdpPreparedProbe *result)
{
    (void)cookie; (void)target;
    memcpy(result->payload, "\x01\x00\x00\x00", 4);
    result->length = 4;
    return 1;
}

static int
ubiquiti_mac(const unsigned char *data)
{
    unsigned i, used = 0;
    if (data[0] & 1) return 0;
    for (i = 0; i < 6; i++) used |= data[i];
    return used != 0;
}

static int
ubiquiti_text(const unsigned char *data, unsigned length)
{
    unsigned i;
    if (length && !data[length - 1]) length--;
    if (length > 255) return 0;
    for (i = 0; i < length; i++) if (data[i] < 32 || data[i] > 126) return 0;
    return 1;
}

int
ubiquiti_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned offset = 4, mac = 0, identity = 0;
    unsigned char seen[256] = {0};
    (void)cookie;
    if (length < 4 || length > 4096 || data[0] != 1 || data[1] ||
        ((unsigned)data[2] << 8 | data[3]) != length - 4) return 0;
    while (offset < length) {
        unsigned type, size, text;
        const unsigned char *value;
        if (length - offset < 3) return 0;
        type = data[offset]; size = (unsigned)data[offset + 1] << 8 | data[offset + 2];
        offset += 3;
        if (size > length - offset) return 0;
        value = data + offset;
        text = type == 3 || type == 11 || type == 12 || type == 13 || type == 20 || type == 21 || type == 22;
        if (type == 1 || type == 10 || type == 15 || text) {
            if (seen[type]) return 0;
            seen[type] = 1;
        }
        if (type == 1 || type == 2) {
            if (size != (type == 1 ? 6u : 10u) || !ubiquiti_mac(value)) return 0;
            mac = 1;
        } else if (type == 10 || type == 15) {
            if (size != 4) return 0;
        } else if (text) {
            if (!ubiquiti_text(value, size)) return 0;
            if (size && value[0] && (type == 3 || type == 12 || type == 20 || type == 21)) identity = 1;
        }
        offset += size;
    }
    return mac && identity;
}
