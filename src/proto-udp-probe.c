#include "proto-udp-probe.h"
#include <string.h>

typedef int (*UDP_PROBE_PREPARE)(uint64_t cookie,
                                 struct UdpPreparedProbe *result);
typedef int (*UDP_PROBE_CLASSIFY)(const unsigned char *response,
                                  unsigned response_length,
                                  uint64_t cookie);

struct UdpProbeSpec {
    unsigned port;
    enum ApplicationProtocol protocol;
    UDP_PROBE_PREPARE prepare;
    UDP_PROBE_CLASSIFY classify;
};

static const struct UdpProbeSpec udp_probe_catalog[] = {
    {0, PROTO_NONE, 0, 0}
};

int
udp_probe_prepare(unsigned port, uint64_t cookie,
                  struct UdpPreparedProbe *result)
{
    unsigned i;

    if (result == NULL)
        return 0;
    memset(result, 0, sizeof(*result));

    for (i = 0; udp_probe_catalog[i].port != 0; i++) {
        if (udp_probe_catalog[i].port != port)
            continue;
        result->port = port;
        return udp_probe_catalog[i].prepare(cookie, result);
    }

    return 0;
}

enum ApplicationProtocol
udp_probe_classify(unsigned port,
                   const unsigned char *response,
                   unsigned response_length,
                   uint64_t cookie)
{
    unsigned i;

    if (response == NULL && response_length != 0)
        return PROTO_NONE;

    for (i = 0; udp_probe_catalog[i].port != 0; i++) {
        if (udp_probe_catalog[i].port != port)
            continue;
        if (udp_probe_catalog[i].classify(response, response_length, cookie))
            return udp_probe_catalog[i].protocol;
        return PROTO_NONE;
    }

    return PROTO_NONE;
}

int
udp_probe_catalog_selftest(void)
{
    struct UdpPreparedProbe result;

    memset(&result, 0xa5, sizeof(result));
    if (udp_probe_prepare(65535, 0, &result) != 0)
        return 1;
    if (result.port != 0 || result.length != 0)
        return 1;
    if (udp_probe_prepare(65535, 0, NULL) != 0)
        return 1;
    if (udp_probe_classify(65535, NULL, 0, 0) != PROTO_NONE)
        return 1;
    if (udp_probe_classify(65535, NULL, 1, 0) != PROTO_NONE)
        return 1;

    return 0;
}
