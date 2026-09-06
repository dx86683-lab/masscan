#ifndef PROTO_UDP_STUN_H
#define PROTO_UDP_STUN_H
#include "proto-udp-probe.h"
#ifdef UDP_EXTENDED_PROBES
int stun_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                        struct UdpPreparedProbe *result);
int stun_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie,
                         const struct UdpProbeTarget *target);
#endif
#endif
