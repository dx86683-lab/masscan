#ifndef PROTO_UDP_PCANYWHERE_H
#define PROTO_UDP_PCANYWHERE_H
#include "proto-udp-probe.h"
int pcanywhere_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                            struct UdpPreparedProbe *result);
int pcanywhere_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
