#ifndef PROTO_UDP_TFTP_H
#define PROTO_UDP_TFTP_H
#include "proto-udp-probe.h"
int tftp_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                        struct UdpPreparedProbe *result);
int tftp_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie,
                         const struct UdpProbeTarget *target);
int tftp_probe_response(const unsigned char *data, unsigned length, uint64_t cookie,
                         const struct UdpProbeTarget *target, time_t timestamp);
#endif
