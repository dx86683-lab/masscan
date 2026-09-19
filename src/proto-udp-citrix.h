#ifndef PROTO_UDP_CITRIX_H
#define PROTO_UDP_CITRIX_H
#include "proto-udp-probe.h"
int citrix_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                         struct UdpPreparedProbe *result);
int citrix_probe_classify(const unsigned char *px, unsigned length,
                          uint64_t cookie);
int citrix_selftest(void);
#endif
