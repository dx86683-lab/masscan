#include "proto-udp-enttec.h"
#include <string.h>

int
enttec_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                      struct UdpPreparedProbe *result)
{
    (void)cookie;
    (void)target;
    memcpy(result->payload, "ESPP\x01", 5);
    result->length = 5;
    return 1;
}

int
enttec_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned i, type;
    (void)cookie;
    if (length != 27 || memcmp(data, "ESPR", 4)) return 0;
    type = (unsigned)data[10] << 8 | data[11];
    switch (type) {
    case 1: case 2: case 4: case 5: case 7: case 8: case 9:
    case 10: case 11: case 0x60: case 0x61: case 0x100: case 0x200:
        break;
    default: return 0;
    }
    for (i = 14; i < 24; i++)
        if (data[i] && (data[i] < 32 || data[i] > 126)) return 0;
    return 1;
}
