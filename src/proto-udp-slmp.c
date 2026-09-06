#include "proto-udp-slmp.h"
#include <string.h>

int
slmp_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                    struct UdpPreparedProbe *result)
{
    (void)target;
    memcpy(result->payload, "\x54\x00\x00\x00\x00\x00\x00\xff\xff\x03\x00\x06\x00\x04\x00\x01\x01\x00\x00", 19);
    result->payload[2] = (unsigned char)cookie;
    result->payload[3] = (unsigned char)(cookie >> 8);
    result->length = 19;
    return 1;
}

int
slmp_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned i, named = 0;
    if (length != 33 || memcmp(data, "\xd4\x00", 2) ||
        data[2] != (unsigned char)cookie || data[3] != (unsigned char)(cookie >> 8) ||
        memcmp(data + 4, "\x00\x00\x00\xff\xff\x03\x00\x14\x00\x00\x00", 11)) return 0;
    for (i = 15; i < 31; i++) {
        if (data[i] < 32 || data[i] > 126) return 0;
        named |= data[i] != 32;
    }
    return named != 0;
}
