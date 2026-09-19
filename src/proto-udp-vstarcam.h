#ifndef PROTO_UDP_VSTARCAM_H
#define PROTO_UDP_VSTARCAM_H
#include "proto-udp-probe.h"

/* UDP 8600 discovery requires source port 8601 for this profile. */
int vstarcam_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                          struct UdpPreparedProbe *result);
/* The 524-byte discovery variant has no request transaction field. */
int vstarcam_probe_classify(const unsigned char *data, unsigned length,
                           uint64_t cookie);
int vstarcam_selftest(void);
#endif
