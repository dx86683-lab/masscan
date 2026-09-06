#ifndef PROTO_UDP_SIP_H
#define PROTO_UDP_SIP_H
#include "proto-udp-probe.h"

int sip_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                      struct UdpPreparedProbe *result);
int sip_probe_classify(const unsigned char *response, unsigned length,
                       uint64_t cookie);
#endif
