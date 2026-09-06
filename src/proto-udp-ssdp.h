#ifndef PROTO_UDP_SSDP_H
#define PROTO_UDP_SSDP_H
#include "proto-udp-probe.h"
int ssdp_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                       struct UdpPreparedProbe *result);
int ssdp_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
