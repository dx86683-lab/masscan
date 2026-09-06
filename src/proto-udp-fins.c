#include "proto-udp-fins.h"
#include <string.h>

static unsigned fins_source, fins_destination;

int
fins_probe_configure(unsigned source_node, unsigned destination_node)
{
    if ((!source_node != !destination_node) || source_node > 254 || destination_node > 254) return 0;
    fins_source = source_node; fins_destination = destination_node;
    return 1;
}

int
fins_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                   struct UdpPreparedProbe *result)
{
    (void)target;
    if (!fins_source || !fins_destination) return 0;
    memcpy(result->payload, "\x80\x00\x02\x00\x00\x00\x00\x00\x00\x00\x05\x01\x00", 13);
    result->payload[4] = (unsigned char)fins_destination;
    result->payload[7] = (unsigned char)fins_source;
    result->payload[9] = (unsigned char)cookie;
    result->length = 13;
    return 1;
}

static int
fins_identity(const unsigned char *data)
{
    unsigned end = 20, i;
    while (end && (!data[end - 1] || data[end - 1] == ' ')) end--;
    if (!end) return 0;
    for (i = 0; i < end; i++) if (data[i] < 32 || data[i] > 126) return 0;
    return 1;
}

int
fins_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    if (!fins_source || !fins_destination || length != 106 ||
        memcmp(data, "\xc0\x00\x02\x00", 4) || data[4] != fins_source ||
        data[5] || data[6] || data[7] != fins_destination || data[8] ||
        data[9] != (unsigned char)cookie || memcmp(data + 10, "\x05\x01\x00\x00", 4)) return 0;
    return fins_identity(data + 14) && fins_identity(data + 34);
}
