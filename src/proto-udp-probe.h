#ifndef PROTO_UDP_PROBE_H
#define PROTO_UDP_PROBE_H

#include <stdint.h>
#include "masscan-app.h"
#include "massip-addr.h"

#define UDP_PROBE_MAX_PAYLOAD 1200

struct UdpPreparedProbe {
    unsigned port;
    unsigned length;
    unsigned char payload[UDP_PROBE_MAX_PAYLOAD];
};

struct UdpProbeTarget {
    ipaddress source;
    ipaddress destination;
    unsigned source_port;
};

int
udp_probe_prepare(unsigned port, uint64_t cookie,
                  const struct UdpProbeTarget *target,
                  struct UdpPreparedProbe *result);

enum ApplicationProtocol
udp_probe_classify(unsigned port,
                   const unsigned char *response,
                   unsigned response_length,
                   uint64_t cookie);

int
udp_probe_catalog_selftest(void);

#endif
