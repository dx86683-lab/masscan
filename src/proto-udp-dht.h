#ifndef PROTO_UDP_DHT_H
#define PROTO_UDP_DHT_H
#include "proto-udp-probe.h"
#ifdef UDP_EXTENDED_PROBES
int dht_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                      struct UdpPreparedProbe *result);
int dht_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
#endif
