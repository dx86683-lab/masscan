#ifndef PROTO_UDP_TEXT_DISCOVERY_H
#define PROTO_UDP_TEXT_DISCOVERY_H
#include "proto-udp-probe.h"
int serialnumberd_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target, struct UdpPreparedProbe *result);
int serialnumberd_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#ifdef UDP_EXTENDED_PROBES
int hikvision_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target, struct UdpPreparedProbe *result);
int hikvision_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
#endif
