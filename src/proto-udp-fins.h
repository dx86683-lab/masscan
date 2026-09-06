#ifndef PROTO_UDP_FINS_H
#define PROTO_UDP_FINS_H
#include "proto-udp-probe.h"
/* Configure once before scanner threads start; (0,0) disables the profile. */
int fins_probe_configure(unsigned source_node, unsigned destination_node);
int fins_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target, struct UdpPreparedProbe *result);
int fins_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
