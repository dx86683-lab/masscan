#ifndef PROTO_UDP_L2TP_H
#define PROTO_UDP_L2TP_H
#include "proto-udp-probe.h"
int l2tp_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                       struct UdpPreparedProbe *result);
int l2tp_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
