#ifndef PROTO_UDP_SNMPV3_H
#define PROTO_UDP_SNMPV3_H
#include "proto-udp-probe.h"
int snmpv3_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                         struct UdpPreparedProbe *result);
int snmpv3_probe_classify(const unsigned char *response, unsigned length, uint64_t cookie);
#endif
