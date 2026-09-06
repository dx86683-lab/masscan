#ifndef PROTO_UDP_UBIQUITI_H
#define PROTO_UDP_UBIQUITI_H
#include "proto-udp-probe.h"
int ubiquiti_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                            struct UdpPreparedProbe *result);
int ubiquiti_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
