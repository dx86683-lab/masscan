#ifndef PROTO_UDP_PLEX_H
#define PROTO_UDP_PLEX_H
#include "proto-udp-probe.h"
int plex_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                        struct UdpPreparedProbe *result);
int plex_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
