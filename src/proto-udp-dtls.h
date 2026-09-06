#ifndef PROTO_UDP_DTLS_H
#define PROTO_UDP_DTLS_H
#include "proto-udp-probe.h"
#ifdef UDP_EXTENDED_PROBES
int dtls_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                       struct UdpPreparedProbe *result);
int dtls_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
#endif
