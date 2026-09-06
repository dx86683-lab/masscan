#ifndef PROTO_UDP_FIXED_DISCOVERY_H
#define PROTO_UDP_FIXED_DISCOVERY_H
#include "proto-udp-probe.h"
int sbus_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target, struct UdpPreparedProbe *result);
int sbus_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
int lantronix_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target, struct UdpPreparedProbe *result);
int lantronix_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
int db2_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target, struct UdpPreparedProbe *result);
int db2_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
int moxa_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target, struct UdpPreparedProbe *result);
int moxa_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
