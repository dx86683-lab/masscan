#ifndef PROTO_UDP_STRUCTURED_DISCOVERY_H
#define PROTO_UDP_STRUCTURED_DISCOVERY_H
#include "proto-udp-probe.h"
int digi_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target, struct UdpPreparedProbe *result);
int digi_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
int sql_anywhere_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target, struct UdpPreparedProbe *result);
int sql_anywhere_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
int hifly_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target, struct UdpPreparedProbe *result);
int hifly_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
int hid_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target, struct UdpPreparedProbe *result);
int hid_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
int gardasoft_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target, struct UdpPreparedProbe *result);
int gardasoft_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
int gardasoft_version_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target, struct UdpPreparedProbe *result);
int gardasoft_version_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie);
#endif
