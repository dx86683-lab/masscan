#ifndef PROTO_UDP_A2S_H
#define PROTO_UDP_A2S_H
#include "proto-udp-probe.h"
int a2s_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                       struct UdpPreparedProbe *result);
int a2s_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
