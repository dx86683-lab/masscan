#ifndef PROTO_UDP_VENTRILO_H
#define PROTO_UDP_VENTRILO_H
#include "proto-udp-probe.h"
int ventrilo_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target, struct UdpPreparedProbe *result);
int ventrilo_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
