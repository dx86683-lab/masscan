#ifndef PROTO_UDP_MDNS_H
#define PROTO_UDP_MDNS_H
#include "proto-udp-probe.h"
int mdns_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                       struct UdpPreparedProbe *result);
int mdns_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
