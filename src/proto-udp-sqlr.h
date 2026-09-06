#ifndef PROTO_UDP_SQLR_H
#define PROTO_UDP_SQLR_H
#include "proto-udp-probe.h"
int sqlr_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                       struct UdpPreparedProbe *result);
int sqlr_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
