#ifndef PROTO_UDP_SLMP_H
#define PROTO_UDP_SLMP_H
#include "proto-udp-probe.h"
int slmp_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                        struct UdpPreparedProbe *result);
int slmp_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
