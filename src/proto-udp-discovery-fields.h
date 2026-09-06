#ifndef PROTO_UDP_DISCOVERY_FIELDS_H
#define PROTO_UDP_DISCOVERY_FIELDS_H
/* Bounded field validators shared by binary and XML discovery envelopes. */
int udp_discovery_ipv4(const unsigned char *data, unsigned length);
int udp_discovery_mac_text(const unsigned char *data, unsigned length);
#endif
