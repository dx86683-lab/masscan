#ifndef PROTO_UDP_ECOM_H
#define PROTO_UDP_ECOM_H
#include "proto-udp-probe.h"

int ecom_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                       struct UdpPreparedProbe *result);
int ecom_probe_classify(const unsigned char *data, unsigned length,
                        uint64_t cookie);
int ecom_selftest(void);

#endif
