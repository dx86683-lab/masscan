#ifndef PROTO_UDP_RUNTIME_H
#define PROTO_UDP_RUNTIME_H
#include <stdint.h>
int udp_probe_runtime_init(void);
#ifdef UDP_EXTENDED_PROBES
int udp_probe_derive(const char *purpose, uint64_t cookie, unsigned char output[32]);
#endif
#endif
