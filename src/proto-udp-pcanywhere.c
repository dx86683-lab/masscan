#include "proto-udp-pcanywhere.h"
#include <string.h>

int
pcanywhere_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                        struct UdpPreparedProbe *result)
{
    (void)cookie; (void)target;
    memcpy(result->payload, "NQ", 2);
    result->length = 2;
    return 1;
}

int
pcanywhere_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned end, i;
    (void)cookie;
    if (length < 12 || length > 1024 || memcmp(data, "NR", 2) ||
        memcmp(data + length - 9, "AHM_3___", 9)) return 0;
    end = length - 9;
    while (end > 2 && data[end - 1] == '_') end--;
    if (end == 2 || end - 2 > 255) return 0;
    for (i = 2; i < end; i++)
        if (data[i] < 32 || data[i] > 126 || data[i] == '_') return 0;
    return 1;
}
