#ifndef PROTO_UDP_ENTTEC_H
#define PROTO_UDP_ENTTEC_H
#include "proto-udp-probe.h"
int enttec_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                          struct UdpPreparedProbe *result);
int enttec_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
