#include "proto-udp-openvpn.h"
#ifdef UDP_EXTENDED_PROBES
#include "proto-udp-runtime.h"
#include <string.h>

int
openvpn_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                      struct UdpPreparedProbe *result)
{
    unsigned char random[32];
    unsigned i, nonzero = 0;
    (void)target;
    if (!udp_probe_derive("openvpn-session", cookie, random)) return 0;
    for (i = 0; i < 8; i++) nonzero |= random[i];
    if (!nonzero) return 0;
    result->payload[0] = 0x38;
    memcpy(result->payload + 1, random, 8);
    memset(result->payload + 9, 0, 5);
    result->length = 14;
    return 1;
}

int
openvpn_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned char random[32];
    unsigned i, nonzero = 0;
    if (length != 26 || data[0] != 0x40 || data[9] != 1 ||
        memcmp(data + 10, "\x00\x00\x00\x00", 4) ||
        memcmp(data + 22, "\x00\x00\x00\x00", 4) ||
        !udp_probe_derive("openvpn-session", cookie, random) ||
        memcmp(data + 14, random, 8)) return 0;
    for (i = 1; i < 9; i++) nonzero |= data[i];
    return nonzero != 0;
}
#endif
