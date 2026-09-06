#include "proto-udp-probe.h"
#include "proto-udp-sip.h"
#include "proto-udp-snmpv3.h"
#include "proto-udp-mdns.h"
#include "proto-udp-sqlr.h"
#include "proto-udp-ssdp.h"
#include "proto-udp-openvpn.h"
#include "proto-udp-runtime.h"
#include "proto-udp-dht.h"
#include "proto-udp-jenkins.h"
#include "proto-udp-dtls.h"
#include "proto-udp-l2tp.h"
#include "proto-udp-ikev1.h"
#include "proto-udp-ikev2.h"
#include "proto-udp-stun.h"
#include "proto-udp-onvif.h"
#include "proto-udp-epm.h"
#include "proto-udp-knx.h"
#include "proto-udp-slmp.h"
#include "proto-udp-enttec.h"
#include "proto-udp-a2s.h"
#include "proto-udp-plex.h"
#include "proto-udp-tftp.h"
#include "proto-udp-ubiquiti.h"
#include "proto-udp-pcanywhere.h"
#include "proto-udp-fixed-discovery.h"
#include "proto-udp-structured-discovery.h"
#include "proto-udp-ventrilo.h"
#include <string.h>
#include "util-safefunc.h"

typedef int (*UDP_PROBE_PREPARE)(uint64_t cookie,
                                 const struct UdpProbeTarget *target,
                                 struct UdpPreparedProbe *result);
typedef int (*UDP_PROBE_CLASSIFY)(const unsigned char *response,
                                  unsigned response_length,
                                  uint64_t cookie);

struct UdpProbeSpec {
    unsigned port;
    enum ApplicationProtocol protocol;
    UDP_PROBE_PREPARE prepare;
    UDP_PROBE_CLASSIFY classify;
    int (*classify_target)(const unsigned char *, unsigned, uint64_t,
                           const struct UdpProbeTarget *);
};

static void
write_u64_be(unsigned char *dst, uint64_t value)
{
    unsigned i;

    for (i = 0; i < 8; i++)
        dst[i] = (unsigned char)(value >> (56 - i * 8));
}

static void
write_u32_be(unsigned char *dst, uint32_t value)
{
    dst[0] = (unsigned char)(value >> 24);
    dst[1] = (unsigned char)(value >> 16);
    dst[2] = (unsigned char)(value >> 8);
    dst[3] = (unsigned char)value;
}

static uint32_t
read_u32_be(const unsigned char *src)
{
    return (uint32_t)src[0] << 24 | (uint32_t)src[1] << 16 |
           (uint32_t)src[2] << 8 | src[3];
}

static int
quic_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
             struct UdpPreparedProbe *result)
{
    (void)target;
    cookie = (uint32_t)cookie;
    memset(result->payload, 0, sizeof(result->payload));
    result->payload[0] = 0xc0;
    result->payload[1] = 0x0a;
    result->payload[2] = 0x0a;
    result->payload[3] = 0x0a;
    result->payload[4] = 0x0a;
    result->payload[5] = 8;
    write_u64_be(result->payload + 6, cookie);
    result->payload[14] = 8;
    write_u64_be(result->payload + 15, ~cookie);
    result->length = UDP_PROBE_MAX_PAYLOAD;
    return 1;
}

static int
quic_classify(const unsigned char *response, unsigned response_length,
              uint64_t cookie)
{
    unsigned offset;
    unsigned dcid_length;
    unsigned scid_length;
    unsigned i;
    unsigned char expected[8];

    cookie = (uint32_t)cookie;

    if (response_length < 15 || (response[0] & 0x80) == 0)
        return 0;
    if (response[1] != 0 || response[2] != 0 ||
        response[3] != 0 || response[4] != 0)
        return 0;

    offset = 5;
    dcid_length = response[offset++];
    if (dcid_length != 8 || offset + dcid_length >= response_length)
        return 0;
    write_u64_be(expected, ~cookie);
    if (memcmp(response + offset, expected, 8) != 0)
        return 0;
    offset += dcid_length;

    scid_length = response[offset++];
    if (scid_length != 8 || offset + scid_length > response_length)
        return 0;
    write_u64_be(expected, cookie);
    if (memcmp(response + offset, expected, 8) != 0)
        return 0;
    offset += scid_length;

    if (response_length - offset == 0 || (response_length - offset) % 4 != 0)
        return 0;
    for (i = offset; i < response_length; i += 4) {
        if (response[i] == 0 && response[i + 1] == 0 &&
            response[i + 2] == 0 && response[i + 3] == 0)
            return 0;
    }
    return 1;
}

static int
bittorrent_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                   struct UdpPreparedProbe *result)
{
    static const unsigned char protocol_id[8] = {
        0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80
    };

    (void)target;
    memcpy(result->payload, protocol_id, sizeof(protocol_id));
    memset(result->payload + 8, 0, 4);
    write_u32_be(result->payload + 12, (uint32_t)cookie);
    result->length = 16;
    return 1;
}

static int
bittorrent_classify(const unsigned char *response, unsigned response_length,
                    uint64_t cookie)
{
    unsigned char expected[4];

    /* BEP 15 permits extensions after the 16-byte connect response. */
    if (response_length < 16)
        return 0;
    if (response[0] != 0 || response[1] != 0 ||
        response[2] != 0 || response[3] != 0)
        return 0;
    write_u32_be(expected, (uint32_t)cookie);
    return memcmp(response + 4, expected, sizeof(expected)) == 0;
}

static int
mumble_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                struct UdpPreparedProbe *result)
{
    (void)target;
    memset(result->payload, 0, 4);
    write_u64_be(result->payload + 4, (uint32_t)cookie);
    result->length = 12;
    return 1;
}

static int
mumble_classify(const unsigned char *response, unsigned response_length,
                uint64_t cookie)
{
    unsigned char expected[8];

    /* Mumble extended Ping echoes an opaque timestamp in a 24-byte reply. */
    if (response_length != 24)
        return 0;
    if (response[0] == 0 && response[1] == 0 &&
        response[2] == 0 && response[3] == 0)
        return 0;
    write_u64_be(expected, (uint32_t)cookie);
    return memcmp(response + 4, expected, sizeof(expected)) == 0;
}

static unsigned
mgcp_transaction(uint64_t cookie)
{
    return (uint32_t)cookie % 999999999U + 1;
}

static int
mgcp_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
              struct UdpPreparedProbe *result)
{
    struct ipaddress_formatted address;
    int length;

    if (target == NULL || (target->destination.version != 4 &&
                           target->destination.version != 6))
        return 0;
    address = ipaddress_fmt(target->destination);
    length = snprintf((char *)result->payload, sizeof(result->payload),
                      "AUEP %u *@[%s] MGCP 1.0\r\n",
                      mgcp_transaction(cookie), address.string);
    if (length < 0 || (unsigned)length >= sizeof(result->payload))
        return 0;
    result->length = (unsigned)length;
    return 1;
}

static int
mgcp_classify(const unsigned char *response, unsigned response_length,
               uint64_t cookie)
{
    unsigned offset = 3;
    unsigned transaction = 0;
    unsigned digits = 0;

    if (response_length < 6 || response[0] < '1' || response[0] > '5' ||
        response[1] < '0' || response[1] > '9' ||
        response[2] < '0' || response[2] > '9' ||
        (response[offset] != ' ' && response[offset] != '\t') ||
        response[response_length - 1] != '\n')
        return 0;
    if (memchr(response, 0, response_length) != NULL)
        return 0;
    while (offset < response_length &&
           (response[offset] == ' ' || response[offset] == '\t'))
        offset++;
    while (offset < response_length && response[offset] >= '0' &&
           response[offset] <= '9') {
        if (++digits > 9)
            return 0;
        transaction = transaction * 10 + response[offset++] - '0';
    }
    if (digits == 0 || transaction != mgcp_transaction(cookie) ||
        offset == response_length)
        return 0;
    if (response[offset] != ' ' && response[offset] != '\t' &&
        response[offset] != '\r' && response[offset] != '\n')
        return 0;
    /* Require a complete first response line, including any CRLF pair. */
    while (offset < response_length && response[offset] != '\n') {
        if (response[offset] == '\r' &&
            (offset + 1 == response_length || response[offset + 1] != '\n'))
            return 0;
        offset++;
    }
    return offset < response_length;
}

static int
slp_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
             struct UdpPreparedProbe *result)
{
    (void)target;
    memset(result->payload, 0, 29);
    result->payload[0] = 2;
    result->payload[1] = 9;
    result->payload[4] = 29;
    result->payload[10] = (unsigned char)(cookie >> 8);
    result->payload[11] = (unsigned char)cookie;
    result->payload[13] = 2;
    result->payload[14] = 'e';
    result->payload[15] = 'n';
    result->payload[18] = result->payload[19] = 0xff;
    result->payload[21] = 7;
    memcpy(result->payload + 22, "DEFAULT", 7);
    result->length = 29;
    return 1;
}

static int
slp_text_valid(const unsigned char *text, unsigned length)
{
    unsigned offset = 0;
    while (offset < length) {
        unsigned value = text[offset++];
        unsigned continuation, minimum;
        if (value < 0x80) {
            if (value < 0x20 || value == 0x7f) return 0;
            continue;
        }
        if (value >= 0xc2 && value <= 0xdf) {
            continuation = 1; minimum = 0x80; value &= 0x1f;
        } else if (value >= 0xe0 && value <= 0xef) {
            continuation = 2; minimum = 0x800; value &= 0x0f;
        } else if (value >= 0xf0 && value <= 0xf4) {
            continuation = 3; minimum = 0x10000; value &= 7;
        } else return 0;
        if (continuation > length - offset) return 0;
        while (continuation--) {
            if ((text[offset] & 0xc0) != 0x80) return 0;
            value = (value << 6) | (text[offset++] & 0x3f);
        }
        if (value < minimum || value > 0x10ffff ||
            (value >= 0xd800 && value <= 0xdfff)) return 0;
    }
    return 1;
}

static int
slp_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    unsigned total, error, list_length;
    if (length < 18 || response[0] != 2 || response[1] != 10) return 0;
    total = (unsigned)response[2] << 16 | (unsigned)response[3] << 8 | response[4];
    if (total != length || response[5] || response[6] || response[7] ||
        response[8] || response[9]) return 0;
    if (response[10] != (unsigned char)(cookie >> 8) ||
        response[11] != (unsigned char)cookie || response[12] != 0 || response[13] != 2 ||
        (response[14] != 'e' && response[14] != 'E') ||
        (response[15] != 'n' && response[15] != 'N')) return 0;
    error = (unsigned)response[16] << 8 | response[17];
    if (error != 0)
        return ((error <= 7) || (error >= 9 && error <= 15)) && length == 18;
    if (length < 20) return 0;
    list_length = (unsigned)response[18] << 8 | response[19];
    return list_length == length - 20 && slp_text_valid(response + 20, list_length);
}

static int
xdmcp_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
               struct UdpPreparedProbe *result)
{
    (void)cookie;
    (void)target;
    memset(result->payload, 0, 7);
    result->payload[1] = 1;
    result->payload[3] = 2;
    result->payload[5] = 1;
    result->length = 7;
    return 1;
}

static int
xdmcp_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    unsigned offset = 6, count;
    (void)cookie;
    if (length < 10 || response[0] != 0 || response[1] != 1 || response[2] != 0 ||
        (response[3] != 5 && response[3] != 6) ||
        ((unsigned)response[4] << 8 | response[5]) != length - 6) return 0;
    count = response[3] == 5 ? 3 : 2;
    while (count--) {
        unsigned size;
        if (length - offset < 2) return 0;
        size = (unsigned)response[offset] << 8 | response[offset + 1];
        offset += 2;
        if (size > length - offset) return 0;
        offset += size;
    }
    return offset == length;
}

static int
ntp_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                  struct UdpPreparedProbe *result)
{
    (void)target;
    memset(result->payload, 0, 48);
    result->payload[0] = 0x23;
    result->payload[2] = 6;
    write_u32_be(result->payload + 40, (uint32_t)cookie);
    write_u32_be(result->payload + 44, ~(uint32_t)cookie);
    result->length = 48;
    return 1;
}

static int
ntp_probe_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    unsigned version, i;
    unsigned char expected[8];
    static const unsigned char zero[8] = {0};
    if (length != 48) return 0;
    version = (response[0] >> 3) & 7;
    if ((version != 3 && version != 4) || (response[0] & 7) != 4 || response[1] > 16)
        return 0;
    write_u32_be(expected, (uint32_t)cookie);
    write_u32_be(expected + 4, ~(uint32_t)cookie);
    if (memcmp(response + 24, expected, 8)) return 0;
    if (response[1] == 0) {
        for (i = 12; i < 16; i++)
            if (response[i] < 'A' || response[i] > 'Z') return 0;
        return 1;
    }
    return memcmp(response + 32, zero, 8) != 0 &&
           memcmp(response + 40, zero, 8) != 0;
}

static int
natpmp_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
               struct UdpPreparedProbe *result)
{
    (void)cookie;
    (void)target;
    result->payload[0] = 0;
    result->payload[1] = 0;
    result->length = 2;
    return 1;
}

static int
natpmp_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    (void)cookie;
    return length == 12 && response[0] == 0 && response[1] == 128 &&
           response[2] == 0 && response[3] <= 5;
}

static int
rpc_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                  struct UdpPreparedProbe *result)
{
    (void)target;
    memset(result->payload, 0, 40);
    write_u32_be(result->payload, (uint32_t)cookie);
    write_u32_be(result->payload + 8, 2);
    write_u32_be(result->payload + 12, 100000);
    write_u32_be(result->payload + 16, 2);
    result->length = 40;
    return 1;
}

static int
rpc_probe_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    unsigned offset, size, padded, status, i;
    if (length < 20 || read_u32_be(response) != (uint32_t)cookie ||
        read_u32_be(response + 4) != 1) return 0;
    status = read_u32_be(response + 8);
    if (status == 1) {
        status = read_u32_be(response + 12);
        if (status == 0)
            return length == 24 && read_u32_be(response + 16) <= read_u32_be(response + 20);
        return status == 1 && length == 20 && read_u32_be(response + 16) >= 1 &&
               read_u32_be(response + 16) <= 14;
    }
    if (status != 0 || length < 24) return 0;
    size = read_u32_be(response + 16);
    if (size > 400) return 0;
    padded = (size + 3) & ~3U;
    offset = 20 + padded;
    if (offset > length - 4) return 0;
    for (i = 20 + size; i < offset; i++)
        if (response[i] != 0) return 0;
    status = read_u32_be(response + offset);
    offset += 4;
    if (status == 2)
        return length - offset == 8 && read_u32_be(response + offset) <=
               read_u32_be(response + offset + 4);
    return status <= 5 && offset == length;
}

static int
gtpu_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
              struct UdpPreparedProbe *result)
{
    (void)target;
    memset(result->payload, 0, 12);
    result->payload[0] = 0x32;
    result->payload[1] = 1;
    result->payload[3] = 4;
    result->payload[8] = (unsigned char)(cookie >> 8);
    result->payload[9] = (unsigned char)cookie;
    result->length = 12;
    return 1;
}

static int
gtpu_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    unsigned offset = 14, size;
    if (length < 14 || (response[0] & 0xf6) != 0x32 || response[1] != 2 ||
        ((unsigned)response[2] << 8 | response[3]) != length - 8 ||
        read_u32_be(response + 4) != 0 ||
        response[8] != (unsigned char)(cookie >> 8) ||
        response[9] != (unsigned char)cookie || response[12] != 14) return 0;
    /* Recovery's counter and unused optional-header fields are ignored. */
    while (offset < length) {
        if (length - offset < 3 || response[offset] != 255) return 0;
        size = (unsigned)response[offset + 1] << 8 | response[offset + 2];
        offset += 3;
        if (size < 2 || size > length - offset) return 0;
        offset += size;
    }
    return 1;
}

static int
rip_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
             struct UdpPreparedProbe *result)
{
    (void)cookie;
    (void)target;
    memset(result->payload, 0, 24);
    result->payload[0] = 1;
    result->payload[1] = 1;
    result->payload[5] = 2;
    result->payload[8] = 192;
    result->payload[10] = 2;
    result->payload[11] = 1;
    result->payload[23] = 16;
    result->length = 24;
    return 1;
}

static int
rip_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    unsigned i;
    (void)cookie;
    if (length != 24 || memcmp(response, "\x02\x01\x00\x00\x00\x02\x00\x00"
                              "\xc0\x00\x02\x01", 12)) return 0;
    for (i = 12; i < 23; i++)
        if (response[i] != 0) return 0;
    return response[23] >= 1 && response[23] <= 16;
}

static int
ipmi_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
              struct UdpPreparedProbe *result)
{
    (void)target;
    memcpy(result->payload, "\x06\x00\xff\x06\x00\x00\x11\xbe\x80\x00\x00\x00", 12);
    result->payload[9] = (unsigned char)((uint32_t)cookie % 255);
    result->length = 12;
    return 1;
}

static int
ipmi_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    return length == 28 &&
           memcmp(response, "\x06\x00\xff\x06\x00\x00\x11\xbe\x40", 9) == 0 &&
           response[9] == (unsigned char)((uint32_t)cookie % 255) &&
           response[10] == 0 && response[11] == 16 && (response[20] & 0x80) != 0;
}

static int
coap_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                   struct UdpPreparedProbe *result)
{
    (void)target;
    result->payload[0] = 0x44;
    result->payload[1] = 1;
    result->payload[2] = (unsigned char)(cookie >> 8);
    result->payload[3] = (unsigned char)cookie;
    write_u32_be(result->payload + 4, (uint32_t)cookie);
    memcpy(result->payload + 8, "\xbb.well-known\x04" "core", 17);
    result->length = 25;
    return 1;
}

static int
coap_option_number(const unsigned char *data, unsigned length, unsigned *offset,
                   unsigned nibble, unsigned *value)
{
    if (nibble < 13) { *value = nibble; return 1; }
    if (nibble == 13 && *offset < length) {
        *value = 13 + data[(*offset)++];
        return 1;
    }
    if (nibble == 14 && length - *offset >= 2) {
        *value = 269 + ((unsigned)data[*offset] << 8 | data[*offset + 1]);
        *offset += 2;
        return 1;
    }
    return 0;
}

static int
coap_probe_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    unsigned offset = 8, number = 0, seen = 0, code;
    if (length < 8 || (response[0] & 0xcf) != 0x44 || (response[0] & 0x30) == 0x30 ||
        read_u32_be(response + 4) != (uint32_t)cookie) return 0;
    if ((response[0] & 0x30) == 0x20 &&
        (((unsigned)response[2] << 8 | response[3]) != (cookie & 0xffff))) return 0;
    code = response[1] >> 5;
    if (code != 2 && code != 4 && code != 5) return 0;
    while (offset < length) {
        unsigned header, delta, size, flag = 0;
        if (response[offset] == 255) return offset + 1 < length;
        header = response[offset++];
        if (!coap_option_number(response, length, &offset, header >> 4, &delta) ||
            !coap_option_number(response, length, &offset, header & 15, &size) ||
            delta > 65535 - number || size > length - offset) return 0;
        number += delta;
        switch (number) {
        case 4: if (size < 1 || size > 8) return 0; break;
        case 8: case 20: if (size > 255) return 0; break;
        case 12: if (size > 2) return 0; flag = 1; break;
        case 14: if (size > 4) return 0; flag = 2; break;
        default: if (number & 1) return 0; break;
        }
        if (flag && (seen & flag)) return 0;
        seen |= flag;
        offset += size;
    }
    return 1;
}

static int
afs_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
             struct UdpPreparedProbe *result)
{
    (void)target;
    memset(result->payload, 0, 29);
    write_u32_be(result->payload + 8, (uint32_t)cookie);
    result->payload[20] = 13;
    result->payload[21] = 5;
    result->length = 29;
    return 1;
}

static int
afs_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    unsigned i;
    unsigned char expected[28] = {0};
    int padding = 0;
    if (length != 93) return 0;
    write_u32_be(expected + 8, (uint32_t)cookie);
    expected[20] = 13;
    expected[21] = 4;
    if (memcmp(response, expected, sizeof(expected)) || response[28] == 0) return 0;
    for (i = 28; i < length; i++) {
        if (response[i] == 0) padding = 1;
        else if (padding || response[i] < 32 || response[i] > 126) return 0;
    }
    return 1;
}

static int
gtpc_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
              struct UdpPreparedProbe *result)
{
    (void)target;
    memcpy(result->payload, "\x40\x01\x00\x09\x00\x00\x00\x00\x03\x00\x01\x00\x00", 13);
    result->payload[4] = (unsigned char)(cookie >> 16);
    result->payload[5] = (unsigned char)(cookie >> 8);
    result->payload[6] = (unsigned char)cookie;
    result->length = 13;
    return 1;
}

static int
gtpc_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    unsigned offset = 8, seen = 0;
    if (length < 13 || (response[0] & 0xf8) != 0x40 || response[1] != 2 ||
        ((unsigned)response[2] << 8 | response[3]) != length - 4 ||
        response[4] != (unsigned char)(cookie >> 16) ||
        response[5] != (unsigned char)(cookie >> 8) ||
        response[6] != (unsigned char)cookie) return 0;
    while (offset < length) {
        unsigned type, size, instance, flag = 0;
        if (length - offset < 4) return 0;
        type = response[offset];
        size = (unsigned)response[offset + 1] << 8 | response[offset + 2];
        instance = response[offset + 3] & 15;
        offset += 4;
        if (size > length - offset) return 0;
        if (type == 3 || type == 152) {
            if (size != 1 || instance != 0) return 0;
            flag = type == 3 ? 1 : 2;
        } else if (type == 255) {
            if (size < 2) return 0;
        } else return 0;
        if (flag && (seen & flag)) return 0;
        seen |= flag;
        offset += size;
    }
    return (seen & 1) != 0;
}

static int
ipmsg_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
               struct UdpPreparedProbe *result)
{
    int length;
    (void)target;
    length = snprintf((char *)result->payload, sizeof(result->payload),
                      "1:%u:scanner:scanner:64:", (unsigned)(uint32_t)cookie);
    if (length < 0 || (unsigned)length >= sizeof(result->payload)) return 0;
    result->length = (unsigned)length + 1;
    return 1;
}

static int
decimal_span(const unsigned char *data, unsigned length, uint64_t limit, uint64_t *value)
{
    unsigned i;
    uint64_t number = 0;
    if (length == 0) return 0;
    for (i = 0; i < length; i++) {
        unsigned digit = data[i] - '0';
        if (digit > 9 || digit > limit || number > (limit - digit) / 10) return 0;
        number = number * 10 + digit;
    }
    *value = number;
    return 1;
}

static int
ipmsg_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    unsigned offset = 0, i;
    uint64_t number;
    (void)cookie;
    if (length < 12 || response[length - 1] != 0) return 0;
    for (i = 0; i < length - 1; i++)
        if (response[i] < 32 || response[i] == 127) return 0;
    for (i = 0; i < 5; i++) {
        unsigned start = offset;
        while (offset < length - 1 && response[offset] != ':') offset++;
        if (offset == length - 1) return 0;
        if (i == 0 && (!decimal_span(response + start, offset - start, 1, &number) || number != 1))
            return 0;
        if (i == 1 && !decimal_span(response + start, offset - start, UINT64_MAX, &number))
            return 0;
        if (i == 4 && (!decimal_span(response + start, offset - start, UINT32_MAX, &number) ||
                      (number & 255) != 65)) return 0;
        offset++;
    }
    return offset < length - 1;
}

static int
enip_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
              struct UdpPreparedProbe *result)
{
    (void)cookie;
    (void)target;
    memset(result->payload, 0, 24);
    result->payload[0] = 0x63;
    result->length = 24;
    return 1;
}

static int
enip_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    unsigned offset = 26, count, i, found = 0;
    (void)cookie;
    if (length < 26 || response[0] != 0x63 || response[1] != 0 ||
        ((unsigned)response[3] << 8 | response[2]) != length - 24) return 0;
    for (i = 4; i < 24; i++)
        if (response[i] != 0) return 0;
    count = (unsigned)response[25] << 8 | response[24];
    for (i = 0; i < count; i++) {
        unsigned type, size;
        if (length - offset < 4) return 0;
        type = (unsigned)response[offset + 1] << 8 | response[offset];
        size = (unsigned)response[offset + 3] << 8 | response[offset + 2];
        offset += 4;
        if (size > length - offset) return 0;
        if (type == 12) {
            if (size < 34 || response[offset] != 1 || response[offset + 1] != 0 ||
                response[offset + 2] != 0 || response[offset + 3] != 2 ||
                (unsigned)response[offset + 32] + 34 != size) return 0;
            found = 1;
        }
        offset += size;
    }
    return found && offset == length;
}

static int
bacnet_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
               struct UdpPreparedProbe *result)
{
    (void)cookie;
    (void)target;
    memcpy(result->payload, "\x81\x0a\x00\x08\x01\x00\x10\x08", 8);
    result->length = 8;
    return 1;
}

static int
bacnet_number(const unsigned char *data, unsigned length, unsigned *offset,
              unsigned tag, uint32_t *value)
{
    unsigned size, i;
    if (*offset >= length || (data[*offset] & 0xf8) != (tag << 4)) return 0;
    size = data[(*offset)++] & 7;
    if (size == 0 || size > 4 || size > length - *offset || (tag == 12 && size != 4)) return 0;
    *value = 0;
    for (i = 0; i < size; i++) *value = (*value << 8) | data[(*offset)++];
    return 1;
}

static int
bacnet_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned control, offset = 6, i;
    uint32_t value;
    (void)cookie;
    if (length < 8 || data[0] != 0x81 || data[1] != 10 ||
        ((unsigned)data[2] << 8 | data[3]) != length || data[4] != 1) return 0;
    control = data[5];
    if (control & 0xd4) return 0;
    for (i = 0; i < 2; i++) {
        unsigned size, network;
        if (!(control & (i == 0 ? 32 : 8))) continue;
        if (length - offset < 3) return 0;
        network = (unsigned)data[offset] << 8 | data[offset + 1];
        size = data[offset + 2];
        offset += 3;
        if (size > length - offset || (i && (!size || network == 65535)) ||
            (!i && network == 65535 && size)) return 0;
        offset += size;
    }
    if (control & 32) {
        if (offset >= length) return 0;
        offset++;
    }
    if (length - offset < 2 || data[offset++] != 0x10 || data[offset++] != 0) return 0;
    if (!bacnet_number(data, length, &offset, 12, &value) || value >> 22 != 8 ||
        (value & 0x3fffff) == 0x3fffff) return 0;
    if (!bacnet_number(data, length, &offset, 2, &value) || !value || value > 65535) return 0;
    if (!bacnet_number(data, length, &offset, 9, &value) || value > 3) return 0;
    if (!bacnet_number(data, length, &offset, 2, &value) || value > 65535) return 0;
    return offset == length;
}

static const struct UdpProbeSpec udp_probe_catalog[] = {
    {80, PROTO_QUIC, quic_prepare, quic_classify},
    {443, PROTO_QUIC, quic_prepare, quic_classify},
    {2491, PROTO_QUIC, quic_prepare, quic_classify},
    {6969, PROTO_BITTORRENT, bittorrent_prepare, bittorrent_classify},
    {64738, PROTO_MUMBLE, mumble_prepare, mumble_classify},
    {2427, PROTO_MGCP, mgcp_prepare, mgcp_classify},
    {6060, PROTO_SIP, sip_probe_prepare, sip_probe_classify},
    {5060, PROTO_SIP, sip_probe_prepare, sip_probe_classify},
    {5061, PROTO_SIP, sip_probe_prepare, sip_probe_classify},
    {427, PROTO_SLP, slp_prepare, slp_classify},
    {177, PROTO_XDMCP, xdmcp_prepare, xdmcp_classify},
    {123, PROTO_NTP, ntp_probe_prepare, ntp_probe_classify},
    {5351, PROTO_NATPMP, natpmp_prepare, natpmp_classify},
    {111, PROTO_RPC, rpc_probe_prepare, rpc_probe_classify},
    {2152, PROTO_GTPU, gtpu_prepare, gtpu_classify},
    {520, PROTO_RIP, rip_prepare, rip_classify},
    {623, PROTO_IPMI, ipmi_prepare, ipmi_classify},
    {5683, PROTO_COAP, coap_probe_prepare, coap_probe_classify},
    {7001, PROTO_AFS, afs_prepare, afs_classify},
    {2123, PROTO_GTPC, gtpc_prepare, gtpc_classify},
    {2425, PROTO_IPMSG, ipmsg_prepare, ipmsg_classify},
    {44818, PROTO_ENIP, enip_prepare, enip_classify},
    {161, PROTO_SNMP, snmpv3_probe_prepare, snmpv3_probe_classify},
    {162, PROTO_SNMP, snmpv3_probe_prepare, snmpv3_probe_classify},
    {391, PROTO_SNMP, snmpv3_probe_prepare, snmpv3_probe_classify},
    {705, PROTO_SNMP, snmpv3_probe_prepare, snmpv3_probe_classify},
    {1993, PROTO_SNMP, snmpv3_probe_prepare, snmpv3_probe_classify},
    {5353, PROTO_MDNS, mdns_probe_prepare, mdns_probe_classify},
    {1434, PROTO_SQL_BROWSER, sqlr_probe_prepare, sqlr_probe_classify},
    {47808, PROTO_BACNET, bacnet_prepare, bacnet_classify},
    {1900, PROTO_SSDP, ssdp_probe_prepare, ssdp_probe_classify},
    {1701, PROTO_L2TP, l2tp_probe_prepare, l2tp_probe_classify},
    {3671, PROTO_KNX, knx_probe_prepare, knx_probe_classify},
    {5006, PROTO_SLMP, slmp_probe_prepare, slmp_probe_classify},
    {5007, PROTO_SLMP, slmp_probe_prepare, slmp_probe_classify},
    {3333, PROTO_ENTTEC, enttec_probe_prepare, enttec_probe_classify},
    {27015, PROTO_A2S, a2s_probe_prepare, a2s_probe_classify},
    {10001, PROTO_UBIQUITI, ubiquiti_probe_prepare, ubiquiti_probe_classify},
    {5632, PROTO_PCANYWHERE, pcanywhere_probe_prepare, pcanywhere_probe_classify},
    {5050, PROTO_SBUS, sbus_probe_prepare, sbus_probe_classify},
    {30718, PROTO_LANTRONIX, lantronix_probe_prepare, lantronix_probe_classify},
    {523, PROTO_DB2, db2_probe_prepare, db2_probe_classify},
    {4800, PROTO_MOXA, moxa_probe_prepare, moxa_probe_classify},
    {2362, PROTO_DIGI, digi_probe_prepare, digi_probe_classify},
    {2638, PROTO_SQL_ANYWHERE, sql_anywhere_probe_prepare, sql_anywhere_probe_classify},
    {48899, PROTO_HIFLY, hifly_probe_prepare, hifly_probe_classify},
    {4070, PROTO_HID, hid_probe_prepare, hid_probe_classify},
    {30311, PROTO_GARDASOFT, gardasoft_probe_prepare, gardasoft_probe_classify},
    {30313, PROTO_GARDASOFT_VERSION, gardasoft_version_probe_prepare, gardasoft_version_probe_classify},
    {3784, PROTO_VENTRILO, ventrilo_probe_prepare, ventrilo_probe_classify},
#ifdef UDP_EXTENDED_PROBES
    {1194, PROTO_OPENVPN, openvpn_probe_prepare, openvpn_probe_classify},
    {6881, PROTO_DHT, dht_probe_prepare, dht_probe_classify},
    {33848, PROTO_JENKINS, jenkins_probe_prepare, jenkins_probe_classify},
    {3391, PROTO_DTLS, dtls_probe_prepare, dtls_probe_classify},
    {4500, PROTO_IKEV1, ikev1_probe_prepare, ikev1_probe_classify},
    {500, PROTO_IKEV2, ikev2_probe_prepare, ikev2_probe_classify},
    {3478, PROTO_STUN, stun_probe_prepare, NULL, stun_probe_classify},
    {3702, PROTO_ONVIF, onvif_probe_prepare, NULL, onvif_probe_classify},
    {34964, PROTO_NONE, epm_probe_prepare, NULL, epm_probe_classify},
    {32414, PROTO_PLEX, plex_probe_prepare, plex_probe_classify},
    {69, PROTO_TFTP_ERROR, tftp_probe_prepare, NULL, tftp_probe_classify},
#endif
    {0, PROTO_NONE, 0, 0}
};

int
udp_probe_is_registered(unsigned port)
{
    unsigned i;
    for (i = 0; udp_probe_catalog[i].port; i++)
        if (udp_probe_catalog[i].port == port) return 1;
    return 0;
}

int
udp_probe_prepare(unsigned port, uint64_t cookie,
                  const struct UdpProbeTarget *target,
                  struct UdpPreparedProbe *result)
{
    unsigned i;

    if (result == NULL)
        return 0;
    memset(result, 0, sizeof(*result));

    for (i = 0; udp_probe_catalog[i].port != 0; i++) {
        if (udp_probe_catalog[i].port != port)
            continue;
        result->port = port;
        return udp_probe_catalog[i].prepare(cookie, target, result);
    }

    return 0;
}

enum ApplicationProtocol
udp_probe_classify(unsigned port,
                   const unsigned char *response,
                   unsigned response_length,
                   uint64_t cookie)
{
    return udp_probe_classify_target(port, response, response_length, cookie, NULL);
}

enum ApplicationProtocol
udp_probe_classify_target(unsigned port, const unsigned char *response,
                           unsigned response_length, uint64_t cookie,
                           const struct UdpProbeTarget *target)
{
    unsigned i;

    if (response == NULL && response_length != 0)
        return PROTO_NONE;

    for (i = 0; udp_probe_catalog[i].port != 0; i++) {
        int identified;
        if (udp_probe_catalog[i].port != port)
            continue;
        identified = udp_probe_catalog[i].classify_target ?
            udp_probe_catalog[i].classify_target(response, response_length, cookie, target) :
            udp_probe_catalog[i].classify(response, response_length, cookie);
        if (identified)
            return udp_probe_catalog[i].protocol != PROTO_NONE ? udp_probe_catalog[i].protocol :
                (enum ApplicationProtocol)identified;
        return PROTO_NONE;
    }

    return PROTO_NONE;
}

enum ApplicationProtocol
udp_probe_classify_timed(unsigned port, const unsigned char *response,
                          unsigned response_length, uint64_t cookie,
                          const struct UdpProbeTarget *target, time_t timestamp)
{
    if (!response) return PROTO_NONE;
#ifdef UDP_EXTENDED_PROBES
    if (port == 69)
        return tftp_probe_response(response, response_length, cookie, target, timestamp) ? PROTO_TFTP_ERROR : PROTO_NONE;
#else
    (void)timestamp;
#endif
    return udp_probe_classify_target(port, response, response_length, cookie, target);
}

#ifdef UDP_EXTENDED_PROBES
static int
plex_fixture_case(const char *original, const char *needle, const char *replacement,
                   int expected)
{
    char changed[4097];
    const char *position = strstr(original, needle);
    size_t prefix, suffix, inserted = strlen(replacement), length;
    if (!position) return 0;
    prefix = (size_t)(position - original);
    suffix = strlen(position + strlen(needle));
    length = prefix + inserted + suffix;
    if (length >= sizeof(changed)) return 0;
    memcpy(changed, original, prefix);
    memcpy(changed + prefix, replacement, inserted);
    memcpy(changed + prefix + inserted, position + strlen(needle), suffix);
    return (udp_probe_classify(32414, (const unsigned char *)changed,
            (unsigned)length, 0) == PROTO_PLEX) == expected;
}

static int
onvif_fixture_case(const char *original, const char *needle, const char *replacement,
                   int expected, uint64_t cookie, const struct UdpProbeTarget *target)
{
    char changed[8192];
    const char *position = strstr(original, needle);
    size_t prefix, suffix, inserted = strlen(replacement), length;
    if (!position) return 0;
    prefix = (size_t)(position - original);
    suffix = strlen(position + strlen(needle));
    length = prefix + inserted + suffix;
    if (length >= sizeof(changed)) return 0;
    memcpy(changed, original, prefix);
    memcpy(changed + prefix, replacement, inserted);
    memcpy(changed + prefix + inserted, position + strlen(needle), suffix);
    return (udp_probe_classify_target(3702, (const unsigned char *)changed,
            (unsigned)length, cookie, target) == PROTO_ONVIF) == expected;
}
#endif

int
udp_probe_catalog_selftest(void)
{
    struct UdpPreparedProbe result;
    static const uint64_t cookie = UINT64_C(0x0000000089abcdef);
    {
        static const unsigned char request[] =
            "\x45\x01\xaf\x24\xde\x6a\xf5\xd9\x66\xef\x80\x08\x3c\x4e\x97\xc0\xf0\x66\x1d\xf6"
            "\x8b\x80\x6a\x93\xe4\x49\x0f\x20\x43\x97\x69\xcd\x8e\x45\x31\x7c";
        static const unsigned char reply[] =
            "\x45\x01\xaf\x24\xde\x6a\xf5\xd9\x66\xf8\x80\x11\x3c\x4e\x97\xc0\xf0\x66\x81\xa1"
            "\xd9\xc1\xb7\xd8\x1e\x69\x5b\x81\xa5\xa1\xbf\x12\xe0\x98\x7a\xcb\x39\xad\x7b\x98\xb0\x66\x23\x9b\x8e";
        unsigned n;
        unsigned char changed[sizeof(reply)];
        {
            static const struct { unsigned length; enum ApplicationProtocol protocol; const char *data; } cases[] = {
                {30, PROTO_NONE,
                    "\x45\x01\xaf\x24\xde\x6a\xf5\xd9\x66\xe9\x80\x02\x3c\x4e\x97\xc0\xf0\x66\xac\x7e\xd9\xc1\xb7\xd8\x1e\x69\x5b\x81\xa5\xa1"},
                {52, PROTO_NONE,
                    "\x45\x01\xaf\x24\xde\x6a\xf5\xd9\x66\xff\x80\x18\x3c\x4e\x97\xc0\xf0\x66\x0e\x1b\xd9\xc1\xb7\xd8\x1e\x69\x5b\x81\xa5\xa1\xbf\x12\xe0\x98\x7a\xcb\x39\xad\x7b\x98\x8c\x8c\x3a\xba\xd7\xd8\xa0\xef\xa6\xba\x9a\x48"},
                {42, PROTO_VENTRILO,
                    "\x45\x01\xaf\x24\xde\x6a\xf5\xd9\x66\xf5\x80\x0e\x3c\x4e\x97\xc0\xf0\x66\xe8\x76\xd9\xc1\xb7\xd8\x1e\x69\x5b\x81\xa5\xa1\xbf\x12\xe0\x98\x7a\xcb\x39\xad\x7b\x98\x8c\x36"},
            };
            for (n = 0; n < sizeof(cases) / sizeof(*cases); n++)
                if (udp_probe_classify(3784, (const unsigned char *)cases[n].data,
                    cases[n].length, 0x1234) != cases[n].protocol) return 1;
        }
        if (udp_probe_classify(3784, reply, sizeof(reply) - 1, 0x1234) != PROTO_VENTRILO) {
            fprintf(stderr, "ventrilo: independent reply rejected\n"); return 1;
        }
        if (!udp_probe_prepare(3784, 0x1234, NULL, &result) || result.length != sizeof(request) - 1 ||
            memcmp(result.payload, request, result.length)) return 1;
        for (n = 0; n < sizeof(reply) - 1; n++) {
            if (udp_probe_classify(3784, reply, n, 0x1234) != PROTO_NONE) return 1;
            memcpy(changed, reply, sizeof(reply)); changed[n] ^= 1;
            if (udp_probe_classify(3784, changed, sizeof(reply) - 1, 0x1234) != PROTO_NONE) return 1;
        }
        if (udp_probe_classify(3784, reply, sizeof(reply) - 1, 0x1235) != PROTO_NONE ||
            udp_probe_classify(3784, reply, sizeof(reply), 0x1234) != PROTO_NONE ||
            udp_probe_classify(3784, request, sizeof(request) - 1, 0x1234) != PROTO_NONE) return 1;
    }
    {
        static const char discovery[] = "Gardasoft,PP420,000001,000B75000001,C0000201";
        static const char version[] = "PP420 (HW001) V002>";
        unsigned n;
        if (udp_probe_classify(30311, (const unsigned char *)discovery, sizeof(discovery) - 1, cookie) != PROTO_GARDASOFT ||
            udp_probe_classify(30313, (const unsigned char *)version, sizeof(version) - 1, cookie) != PROTO_GARDASOFT_VERSION) {
            fprintf(stderr, "gardasoft: complete reply rejected\n"); return 1;
        }
        if (!udp_probe_prepare(30311, cookie, NULL, &result) || result.length != 16 ||
            memcmp(result.payload, "Gardasoft Search", 16)) return 1;
        if (!udp_probe_prepare(30313, cookie, NULL, &result) || result.length != 3 ||
            memcmp(result.payload, "VR\r", 3)) return 1;
        for (n = 0; n < sizeof(discovery) - 1; n++)
            if (udp_probe_classify(30311, (const unsigned char *)discovery, n, cookie) != PROTO_NONE) return 1;
        for (n = 0; n < sizeof(version) - 1; n++)
            if (udp_probe_classify(30313, (const unsigned char *)version, n, cookie) != PROTO_NONE) return 1;
        if (udp_probe_classify(30310, (const unsigned char *)discovery, sizeof(discovery) - 1, cookie) != PROTO_NONE ||
            udp_probe_classify(30312, (const unsigned char *)version, sizeof(version) - 1, cookie) != PROTO_NONE) return 1;
        {
            static const char alternate[] = "Gardasoft,TR-RC120,000001,000B75000001,C0000201";
            static const char *bad_version[] = {">", "Err 2>", "PP420 (HW001) V00X>", "PP420 (HW001) V002>extra", "VRPP420 (HW001) V002>"};
            static const unsigned offsets[] = {0, 10, 15, 21, 23, 35};
            unsigned char changed[64];
            if (udp_probe_classify(30311, (const unsigned char *)alternate, sizeof(alternate) - 1, cookie) != PROTO_GARDASOFT) return 1;
            for (n = 0; n < sizeof(offsets) / sizeof(*offsets); n++) {
                memcpy(changed, discovery, sizeof(discovery)); changed[offsets[n]] = '!';
                if (udp_probe_classify(30311, changed, sizeof(discovery) - 1, cookie) != PROTO_NONE) return 1;
            }
            if (udp_probe_classify(30311, (const unsigned char *)discovery, sizeof(discovery), cookie) != PROTO_NONE) return 1;
            for (n = 0; n < sizeof(bad_version) / sizeof(*bad_version); n++)
                if (udp_probe_classify(30313, (const unsigned char *)bad_version[n], (unsigned)strlen(bad_version[n]), cookie) != PROTO_NONE) return 1;
            {
                static const char echoed[] = "VR\r\nPP420 (HW001) V002\r\n>\r\n";
                if (udp_probe_classify(30313, (const unsigned char *)echoed, sizeof(echoed) - 1, cookie) != PROTO_GARDASOFT_VERSION) return 1;
            }
        }
    }
    {
        static const struct {
            unsigned port, length;
            enum ApplicationProtocol protocol;
            const char *reply;
        } fixtures[] = {
            {2362, 25, PROTO_DIGI, "DIGI\x00\x02\x00\x11\x01\x06\x02\x00\x00\x00\x00\x01\x0d\x07" "TestBox"},
            {2638, 64, PROTO_SQL_ANYWHERE,
                "\x1b\x00\x00\x40\x00\x00\x00\x00\x12" "CONNECTIONLESS_TDS\x00"
                "\x00\x00\x01\x01\x00\x04\x00\x05\x00\x05\x00\x03" "db\x00"
                "\x01\x02\x0a\x4e\x03\x01\x02\x04\x08\x00\x00\x00\x00\x00\x00\x00\x00\x07\x02\x04\xb1"},
            {48899, 35, PROTO_HIFLY, "192.0.2.10,020000000001,TEST-MODULE"},
            {4070, 87, PROTO_HID, "discovered;087;00-06-8E-12-34-56;VertXController;192.0.2.1;2;V2000;2.2.7.18;02/27/2007;"}
        };
        unsigned f, n;
        for (f = 0; f < sizeof(fixtures) / sizeof(*fixtures); f++) {
            unsigned char changed[128];
            unsigned length = fixtures[f].length, port = fixtures[f].port;
            const unsigned char *reply = (const unsigned char *)fixtures[f].reply;
            if (udp_probe_classify(port, reply, length, cookie) != fixtures[f].protocol) {
                fprintf(stderr, "structured discovery: reply rejected on %u\n", port); return 1;
            }
            for (n = 0; n < (port == 48899 ? 25u : length); n++)
                if (udp_probe_classify(port, reply, n, cookie) != PROTO_NONE) return 1;
            memcpy(changed, reply, length); changed[length] = 0;
            if (udp_probe_classify(port, changed, length + 1, cookie) != PROTO_NONE) return 1;
            changed[0] = '!';
            if (udp_probe_classify(port, changed, length, cookie) != PROTO_NONE) return 1;
            if (!udp_probe_prepare(port, cookie, NULL, &result) ||
                udp_probe_classify(port, result.payload, result.length, cookie) != PROTO_NONE) return 1;
            if (port == 48899 && (result.length != 17 || memcmp(result.payload, "HF-A11ASSISTHREAD", 17))) {
                fprintf(stderr, "hifly: discovery string truncated\n"); return 1;
            }
            if (port == 2638 && result.length != 61) return 1;
            if (port == 4070 && (result.length != 13 || memcmp(result.payload, "discover;013;", 13))) return 1;
            if (port == 2362 && (result.length != 14 || memcmp(result.payload,
                "DIGI\x00\x01\x00\x06\xff\xff\xff\xff\xff\xff", 14))) return 1;
            memcpy(changed, reply, length);
            if (port == 2362) {
                memcpy(changed + length, "\x11\x01\x03", 3); changed[7] += 3;
                if (udp_probe_classify(port, changed, length + 3, cookie) != PROTO_NONE) return 1;
                changed[length + 2] = 2;
                if (udp_probe_classify(port, changed, length + 3, cookie) != PROTO_DIGI) return 1;
                changed[length] = 0x80;
                if (udp_probe_classify(port, changed, length + 3, cookie) != PROTO_DIGI) return 1;
                changed[length] = 1;
                if (udp_probe_classify(port, changed, length + 3, cookie) != PROTO_NONE) return 1;
                memcpy(changed, reply, length); changed[10] = 3;
                if (udp_probe_classify(port, changed, length, cookie) != PROTO_NONE) return 1;
            } else if (port == 2638) {
                static const unsigned offsets[] = {3, 8, 31, 39, 42, 43, 47, 63};
                for (n = 0; n < sizeof(offsets) / sizeof(*offsets); n++) {
                    memcpy(changed, reply, length); changed[offsets[n]] ^= 1;
                    if (udp_probe_classify(port, changed, length, cookie) != PROTO_NONE) return 1;
                }
                memcpy(changed, reply, length); changed[45] = changed[46] = 0;
                if (udp_probe_classify(port, changed, length, cookie) != PROTO_NONE) return 1;
            } else if (port == 48899) {
                static const char *bad[] = {"999.0.2.10,020000000001,TEST", "192.0.2.10,030000000001,TEST",
                    "192.0.2.10,000000000000,TEST", "192.0.2.10,020000000001,TEST,EXTRA",
                    "192.0.2.10,020000000001,TEST\r"};
                for (n = 0; n < sizeof(bad) / sizeof(*bad); n++)
                    if (udp_probe_classify(port, (const unsigned char *)bad[n], (unsigned)strlen(bad[n]), cookie) != PROTO_NONE) return 1;
                memcpy(changed, reply, length); changed[length] = '\r'; changed[length + 1] = '\n';
                if (udp_probe_classify(port, changed, length + 2, cookie) != PROTO_HIFLY) return 1;
            } else {
                static const unsigned offsets[] = {11, 15, 33, 47, 69, 75};
                for (n = 0; n < sizeof(offsets) / sizeof(*offsets); n++) {
                    memcpy(changed, reply, length); changed[offsets[n]] = '!';
                    if (udp_probe_classify(port, changed, length, cookie) != PROTO_NONE) return 1;
                }
                memcpy(changed, reply, length);
                memcpy(changed + length - 11, "02/29/2007", 10);
                if (udp_probe_classify(port, changed, length, cookie) != PROTO_NONE) return 1;
                changed[length - 2] = '8';
                if (udp_probe_classify(port, changed, length, cookie) != PROTO_HID) return 1;
            }
        }
    }
    {
        static const struct {
            unsigned port;
            enum ApplicationProtocol protocol;
            const char *query, *reply;
            unsigned query_length, reply_length;
        } fixtures[] = {
            {5050, PROTO_SBUS, "\x00\x00\x00\x0d\x00\x00\x12\x34\x00\xff\x1d\x30\xc6",
                "\x00\x00\x00\x0c\x00\x00\x12\x34\x01\x07\xfe\x17", 13, 12},
            {30718, PROTO_LANTRONIX, "\x00\x00\x00\xf6",
                "\x00\x00\x00\xf7\x00\x00\x00\x00\x33\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x20\x4a\x12\x34\x56", 4, 30},
            {523, PROTO_DB2, "DB2GETADDR\x00" "SQL09010\x00",
                "DB2RETADDR\x00" "SQL09070\x00" "dbhost\x00", 20, 27},
            {4800, PROTO_MOXA, "\x01\x00\x00\x08\x00\x00\x00\x00",
                "\x81\x00\x00\x18\x00\x00\x00\x00\x00\x60\x00\x80\x50\x62\x00\x90\xe8\x00\x00\x01\xc0\x00\x02\x01", 8, 24}
        };
        unsigned f, n;
        for (f = 0; f < sizeof(fixtures) / sizeof(*fixtures); f++) {
            unsigned char changed[64];
            const unsigned char *reply = (const unsigned char *)fixtures[f].reply;
            unsigned port = fixtures[f].port, length = fixtures[f].reply_length;
            if (udp_probe_classify(port, reply, length, 0x1234) != fixtures[f].protocol) {
                fprintf(stderr, "discovery: complete reply rejected on %u\n", port); return 1;
            }
            if (!udp_probe_prepare(port, 0x1234, NULL, &result) || result.length != fixtures[f].query_length ||
                memcmp(result.payload, fixtures[f].query, result.length)) return 1;
            for (n = 0; n < length; n++)
                if (udp_probe_classify(port, reply, n, 0x1234) != PROTO_NONE) return 1;
            memcpy(changed, reply, length); changed[length] = 0;
            if (udp_probe_classify(port, changed, length + 1, 0x1234) != PROTO_NONE) return 1;
            changed[0] ^= 1;
            if (udp_probe_classify(port, changed, length, 0x1234) != PROTO_NONE) return 1;
            if (udp_probe_classify(port, result.payload, result.length, 0x1234) != PROTO_NONE) return 1;
            memcpy(changed, reply, length);
            if (port == 5050) {
                static const unsigned char wrong_id[] = "\x00\x00\x00\x0c\x00\x00\x12\x34\x01\x07\xfe\x17";
                if (udp_probe_classify(port, wrong_id, 12, 0x1235) != PROTO_NONE) return 1;
                for (n = 0; n < length; n++) {
                    memcpy(changed, reply, length); changed[n] ^= 1;
                    if (udp_probe_classify(port, changed, length, 0x1234) != PROTO_NONE) return 1;
                }
            } else if (port == 30718) {
                changed[24] |= 1;
                if (udp_probe_classify(port, changed, length, 0x1234) != PROTO_NONE) return 1;
                memset(changed + 24, 0, 6);
                if (udp_probe_classify(port, changed, length, 0x1234) != PROTO_NONE) return 1;
            } else if (port == 523) {
                static const unsigned offsets[] = {10, 14, 19, 20, 26};
                for (n = 0; n < sizeof(offsets) / sizeof(*offsets); n++) {
                    memcpy(changed, reply, length); changed[offsets[n]] = '!';
                    if (udp_probe_classify(port, changed, length, 0x1234) != PROTO_NONE) return 1;
                }
                memcpy(changed, reply, length); changed[23] = 0;
                if (udp_probe_classify(port, changed, length, 0x1234) != PROTO_NONE) return 1;
            } else {
                changed[1] = 4;
                if (udp_probe_classify(port, changed, length, 0x1234) != PROTO_NONE) return 1;
                memcpy(changed, reply, length); changed[14] = 2;
                if (udp_probe_classify(port, changed, length, 0x1234) != PROTO_NONE) return 1;
                memcpy(changed, reply, length); changed[3]--;
                if (udp_probe_classify(port, changed, length, 0x1234) != PROTO_NONE) return 1;
            }
        }
    }
    {
        static const unsigned char padded[] = "NRLAB___AHM_3___";
        static const unsigned char plain[] = "NRLABAHM_3___";
        static const char *invalid[] = {
            "NRAHM_3___", "NQLAB___AHM_3___", "nrLAB___AHM_3___",
            "NRLA_B___AHM_3___", "NRLAB___AHM_4___", "NRLA\nB___AHM_3___"
        };
        unsigned n;
        if (udp_probe_classify(5632, padded, sizeof(padded), cookie) != PROTO_PCANYWHERE ||
            udp_probe_classify(5632, plain, sizeof(plain), cookie) != PROTO_PCANYWHERE) {
            fprintf(stderr, "pcanywhere: complete reply rejected\n"); return 1;
        }
        if (!udp_probe_prepare(5632, cookie, NULL, &result) || result.length != 2 ||
            memcmp(result.payload, "NQ", 2)) return 1;
        for (n = 0; n < sizeof(padded); n++)
            if (udp_probe_classify(5632, padded, n, cookie) != PROTO_NONE) return 1;
        for (n = 0; n < sizeof(invalid) / sizeof(*invalid); n++)
            if (udp_probe_classify(5632, (const unsigned char *)invalid[n],
                    (unsigned)strlen(invalid[n]) + 1, cookie) != PROTO_NONE) return 1;
        {
            unsigned char changed[sizeof(padded) + 1];
            memcpy(changed, padded, sizeof(padded)); changed[sizeof(padded)] = 0;
            if (udp_probe_classify(5632, changed, sizeof(changed), cookie) != PROTO_NONE) return 1;
            changed[3] = 0;
            if (udp_probe_classify(5632, changed, sizeof(padded), cookie) != PROTO_NONE) return 1;
        }
    }
    {
        static const unsigned char reply[] =
            "\x01\x00\x00\x13\x01\x00\x06\x02\x00\x00\x00\x00\x01\x14\x00\x07" "TestBox";
        if (udp_probe_classify(10001, reply, sizeof(reply) - 1, cookie) != PROTO_UBIQUITI) return 1;
        {
            unsigned char changed[64];
            struct UdpPreparedProbe request;
            unsigned n, length = sizeof(reply) - 1;
            if (!udp_probe_prepare(10001, cookie, NULL, &request) || request.length != 4 ||
                memcmp(request.payload, "\x01\x00\x00\x00", 4)) return 1;
            for (n = 0; n < length; n++)
                if (udp_probe_classify(10001, reply, n, cookie) != PROTO_NONE) return 1;
            memcpy(changed, reply, length);
            memcpy(changed + length, "\x0d\x00\x00", 3);
            changed[3] += 3;
            if (udp_probe_classify(10001, changed, length + 3, cookie) != PROTO_UBIQUITI) {
                fprintf(stderr, "ubiquiti: empty optional text rejected\n"); return 1;
            }
            changed[length] = 0x80;
            if (udp_probe_classify(10001, changed, length + 3, cookie) != PROTO_UBIQUITI) return 1;
            changed[length] = 0x14;
            if (udp_probe_classify(10001, changed, length + 3, cookie) != PROTO_NONE) return 1;
            for (n = 0; n < 8; n++) {
                memcpy(changed, reply, length);
                switch (n) {
                case 0: changed[0] = 2; break;
                case 1: changed[1] = 1; break;
                case 2: changed[3]--; break;
                case 3: changed[6] = 5; break;
                case 4: changed[7] = 3; break;
                case 5: memset(changed + 7, 0, 6); break;
                case 6: changed[13] = 0x80; break;
                default: changed[18] = 0; break;
                }
                if (udp_probe_classify(10001, changed, length, cookie) != PROTO_NONE) return 1;
            }
        }
    }
    {
        static const unsigned char reply[] =
            "\xff\xff\xff\xff\x49\x11" "Test\x00" "map\x00" "folder\x00" "Game\x00"
            "\x0a\x00\x01\x10\x00" "dl\x00\x01" "1.0\x00";
        if (udp_probe_classify(27015, reply, sizeof(reply) - 1, cookie) != PROTO_A2S) return 1;
        {
            unsigned char changed[100];
            unsigned n = sizeof(reply) - 1;
            memcpy(changed, reply, n);
            changed[n] = 0;
            if (udp_probe_classify(27015, changed, n + 1, cookie) != PROTO_A2S) return 1;
            changed[n] = 0xf1;
            memcpy(changed + n + 1, "\x87\x69\x01\x00\x00\x00\x00\x00\x00\x00\x88\x69" "TV\x00" "tag\x00" "\x0a\x00\x00\x00\x00\x00\x00\x00", 27);
            if (udp_probe_classify(27015, changed, n + 28, cookie) != PROTO_A2S) return 1;
            {
                unsigned j;
                if (!udp_probe_prepare(27015, cookie, NULL, &result) || result.length != 25 ||
                    memcmp(result.payload, "\xff\xff\xff\xff\x54" "Source Engine Query", 25)) return 1;
                for (j = 0; j < n; j++)
                    if (udp_probe_classify(27015, reply, j, cookie) != PROTO_NONE) return 1;
                for (j = n + 1; j < n + 28; j++)
                    if (udp_probe_classify(27015, changed, j, cookie) != PROTO_NONE) return 1;
                changed[n] = 2;
                if (udp_probe_classify(27015, changed, n + 1, cookie) != PROTO_NONE) return 1;
                memcpy(changed, reply, n); changed[4] = 0x41;
                if (udp_probe_classify(27015, changed, 9, cookie) != PROTO_NONE) return 1;
                changed[4] = 0x49; changed[0] = 0xfe;
                if (udp_probe_classify(27015, changed, n, cookie) != PROTO_NONE) return 1;
                memcpy(changed, reply, n); changed[32] = 'x';
                if (udp_probe_classify(27015, changed, n, cookie) != PROTO_NONE) return 1;
                memcpy(changed, reply, n); changed[34] = 2;
                if (udp_probe_classify(27015, changed, n, cookie) != PROTO_NONE) return 1;
                memcpy(changed, reply, n); changed[27] = 0x60; changed[28] = 9;
                memmove(changed + 39, changed + 36, n - 36);
                memset(changed + 36, 0, 3);
                if (udp_probe_classify(27015, changed, n + 3, cookie) != PROTO_A2S) return 1;
            }
        }
    }
    {
        static const unsigned char reply[] =
            "ESPR\x02\x00\x00\x00\x00\x01\x00\x0a\x01\x00"
            "Test Node \x00\x00\x40";
        if (udp_probe_classify(3333, reply, sizeof(reply) - 1, cookie) != PROTO_ENTTEC) return 1;
        {
            unsigned j;
            unsigned char changed[28];
            if (!udp_probe_prepare(3333, cookie, NULL, &result) || result.length != 5 ||
                memcmp(result.payload, "ESPP\x01", 5)) return 1;
            for (j = 0; j < 27; j++)
                if (udp_probe_classify(3333, reply, j, cookie) != PROTO_NONE) return 1;
            for (j = 0; j < 4; j++) {
                memcpy(changed, reply, 27); changed[j] ^= 1;
                if (udp_probe_classify(3333, changed, 27, cookie) != PROTO_NONE) return 1;
            }
            memcpy(changed, reply, 27);
            changed[10] = 255;
            if (udp_probe_classify(3333, changed, 27, cookie) != PROTO_NONE) return 1;
            changed[10] = 0; changed[11] = 11;
            memset(changed + 14, 'A', 10);
            if (udp_probe_classify(3333, changed, 27, cookie) != PROTO_ENTTEC) return 1;
            changed[23] = 1;
            if (udp_probe_classify(3333, changed, 27, cookie) != PROTO_NONE) return 1;
            memset(changed + 14, 0, 10);
            if (udp_probe_classify(3333, changed, 27, cookie) != PROTO_ENTTEC) return 1;
            changed[27] = 0;
            if (udp_probe_classify(3333, changed, 28, cookie) != PROTO_NONE) return 1;
        }
    }
    {
        static const unsigned char reply[] =
            "\xd4\x00\x34\x12\x00\x00\x00\xff\xff\x03\x00\x14\x00\x00\x00"
            "Q02UCPU         \x63\x02";
        if (udp_probe_classify(5007, reply, sizeof(reply) - 1, 0x1234) != PROTO_SLMP) return 1;
        {
            unsigned j, port;
            unsigned char changed[34];
            for (port = 5006; port <= 5007; port++) {
                if (!udp_probe_prepare(port, 0x1234, NULL, &result) || result.length != 19 ||
                    memcmp(result.payload, "\x54\x00\x34\x12\x00\x00\x00\xff\xff\x03\x00\x06\x00\x04\x00\x01\x01\x00\x00", 19)) return 1;
                if (udp_probe_classify(port, reply, 33, 0x1234) != PROTO_SLMP) return 1;
                for (j = 0; j < 33; j++)
                    if (udp_probe_classify(port, reply, j, 0x1234) != PROTO_NONE) return 1;
                for (j = 0; j < 15; j++) {
                    memcpy(changed, reply, 33); changed[j] ^= 1;
                    if (udp_probe_classify(port, changed, 33, 0x1234) != PROTO_NONE) return 1;
                }
                if (udp_probe_classify(port, reply, 33, 0x1235) != PROTO_NONE) return 1;
                memcpy(changed, reply, 33); changed[33] = 0;
                if (udp_probe_classify(port, changed, 34, 0x1234) != PROTO_NONE) return 1;
                memset(changed + 15, ' ', 16);
                if (udp_probe_classify(port, changed, 33, 0x1234) != PROTO_NONE) return 1;
                memset(changed + 15, 'A', 16); changed[31] = changed[32] = 255;
                if (udp_probe_classify(port, changed, 33, 0x1234) != PROTO_SLMP) return 1;
                changed[30] = 0;
                if (udp_probe_classify(port, changed, 33, 0x1234) != PROTO_NONE) return 1;
            }
        }
    }
    {
        static const unsigned char reply[] =
            "\x06\x10\x02\x0c\x00\x48\x08\x01\xc0\x00\x02\x01\x0e\x57"
            "\x36\x01\x02\x00\x11\x01\x00\x01\x00\x01\x02\x03\x04\x05\xe0\x00\x17\x0c\x02\x00\x00\x00\x00\x01"
            "KNX test\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x04\x02\x02\x02";
        if (udp_probe_classify(3671, reply, sizeof(reply) - 1, cookie) != PROTO_KNX) return 1;
        {
            unsigned char changed[100];
            unsigned j;
            if (!udp_probe_prepare(3671, cookie, NULL, &result) || result.length != 18 ||
                memcmp(result.payload, "\x06\x10\x02\x0b\x00\x12\x08\x01\x00\x00\x00\x00\x00\x00\x04\x84\x02\x01", 18)) return 1;
            for (j = 0; j < sizeof(reply) - 1; j++)
                if (udp_probe_classify(3671, reply, j, cookie) != PROTO_NONE) return 1;
            memcpy(changed, reply, 72);
            changed[5] = 74; changed[72] = 2; changed[73] = 128;
            if (udp_probe_classify(3671, changed, 74, cookie) != PROTO_KNX) return 1;
            changed[73] = 3;
            if (udp_probe_classify(3671, changed, 74, cookie) != PROTO_NONE) return 1;
            for (j = 0; j < 8; j++) {
                memcpy(changed, reply, 72); changed[j] ^= 0x80;
                if (udp_probe_classify(3671, changed, 72, cookie) != PROTO_NONE) return 1;
            }
            memcpy(changed, reply, 72);
            memcpy(changed + 14, reply + 68, 4); memcpy(changed + 18, reply + 14, 54);
            if (udp_probe_classify(3671, changed, 72, cookie) != PROTO_KNX) return 1;
            memcpy(changed, reply, 72); memset(changed + 38, 0xe9, 30);
            changed[8] = 10;
            if (udp_probe_classify(3671, changed, 72, cookie) != PROTO_KNX) return 1;
            memset(changed + 8, 0, 4);
            if (udp_probe_classify(3671, changed, 72, cookie) != PROTO_NONE) return 1;
            memset(changed + 12, 0, 2);
            if (udp_probe_classify(3671, changed, 72, cookie) != PROTO_KNX) return 1;
            memcpy(changed, reply, 72); changed[5] = 76;
            memcpy(changed + 72, reply + 68, 4);
            if (udp_probe_classify(3671, changed, 76, cookie) != PROTO_NONE) return 1;
            changed[73] = 254;
            if (udp_probe_classify(3671, changed, 76, cookie) != PROTO_KNX) return 1;
            memcpy(changed, reply, 72); changed[5] = 68;
            if (udp_probe_classify(3671, changed, 68, cookie) != PROTO_NONE) return 1;
            memcpy(changed, reply, 72); changed[5] = 74; changed[68] = 6;
            changed[72] = 2; changed[73] = 1;
            if (udp_probe_classify(3671, changed, 74, cookie) != PROTO_NONE) return 1;
            changed[72] = 4;
            if (udp_probe_classify(3671, changed, 74, cookie) != PROTO_KNX) return 1;
            memcpy(changed, reply, 72); changed[5] = 80;
            memcpy(changed + 72, "\x08\x08\x00\x00\x00\x0f\x09\x1a", 8);
            if (udp_probe_classify(3671, changed, 80, cookie) != PROTO_KNX) return 1;
            changed[72] = 7;
            if (udp_probe_classify(3671, changed, 80, cookie) != PROTO_NONE) return 1;
        }
    }
    unsigned char version_negotiation[31] = {
        0xc0, 0x00, 0x00, 0x00, 0x00,
        0x08, 0xff, 0xff, 0xff, 0xff, 0x76, 0x54, 0x32, 0x10,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x89, 0xab, 0xcd, 0xef,
        0x00, 0x00, 0x00, 0x01,
        0x6b, 0x33, 0x43, 0xcf
    };
    unsigned char tracker_response[16] = {
        0x00, 0x00, 0x00, 0x00,
        0x89, 0xab, 0xcd, 0xef,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };
    unsigned char invalid[sizeof(version_negotiation)];
    unsigned char mumble_response[25] = {
        0x00, 0x01, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x89, 0xab, 0xcd, 0xef,
        0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x20,
        0x00, 0x01, 0x1f, 0x40, 0x00
    };
    unsigned i;

    {
        static const unsigned char reply[] =
            "\xc8\x02\x00\x3b\xcd\xef\x00\x00\x00\x00\x00\x01"
            "\x80\x08\x00\x00\x00\x00\x00\x02"
            "\x80\x08\x00\x00\x00\x02\x01\x00"
            "\x80\x0d\x00\x00\x00\x07scanner"
            "\x80\x0a\x00\x00\x00\x03\x00\x00\x00\x00"
            "\x80\x08\x00\x00\x00\x09\x12\x34";
        if (udp_probe_classify(1701, reply, sizeof(reply) - 1, cookie) != PROTO_L2TP) return 1;
        {
            unsigned char changed[128];
            static const unsigned offsets[] = {0, 2, 3, 4, 5, 6, 8, 10, 11, 12, 13, 14, 17, 19, 23, 26, 27, 33, 52};
            if (!udp_probe_prepare(1701, cookie, NULL, &result) || result.length != 59 ||
                result.payload[4] || result.payload[5] || result.payload[11] || result.payload[19] != 1 ||
                result.payload[57] != 0xcd || result.payload[58] != 0xef) return 1;
            if (udp_probe_classify(1701, result.payload, result.length, cookie) != PROTO_NONE) return 1;
            for (i = 0; i < sizeof(reply) - 1; i++)
                if (udp_probe_classify(1701, reply, i, cookie) != PROTO_NONE) return 1;
            if (udp_probe_classify(1701, reply, sizeof(reply) - 1, cookie ^ 1) != PROTO_NONE) return 1;
            for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
                memcpy(changed, reply, sizeof(reply));
                changed[offsets[i]] ^= 0x80;
                if (udp_probe_classify(1701, changed, sizeof(reply) - 1, cookie) != PROTO_NONE) return 1;
            }
            memcpy(changed, reply, sizeof(reply));
            changed[0] |= 0x04; /* Reserved control-header bit is ignored. */
            if (udp_probe_classify(1701, changed, 59, cookie) != PROTO_L2TP) return 1;
            changed[57] = changed[58] = 0;
            if (udp_probe_classify(1701, changed, 59, cookie) != PROTO_NONE) return 1;
            memcpy(changed, reply, sizeof(reply));
            changed[3] = 65;
            memcpy(changed + 59, "\x00\x06\x12\x34\x00\x01", 6);
            if (udp_probe_classify(1701, changed, 65, cookie) != PROTO_L2TP) return 1;
            changed[59] = 0x80;
            if (udp_probe_classify(1701, changed, 65, cookie) != PROTO_NONE) return 1;
            changed[3] = 67;
            memcpy(changed + 59, "\x80\x08\x00\x00\x00\x0a\x00\x04", 8);
            if (udp_probe_classify(1701, changed, 67, cookie) != PROTO_L2TP) return 1;
            changed[66] = 0;
            if (udp_probe_classify(1701, changed, 67, cookie) != PROTO_NONE) return 1;
            memcpy(changed + 59, reply + 20, 8);
            if (udp_probe_classify(1701, changed, 67, cookie) != PROTO_NONE) return 1;
            memcpy(changed, reply, sizeof(reply));
            changed[28] |= 0x40;
            if (udp_probe_classify(1701, changed, 59, cookie) != PROTO_NONE) return 1;
            changed[28] = 0;
            if (udp_probe_classify(1701, changed, 59, cookie) != PROTO_NONE) return 1;
            if (!udp_probe_prepare(1701, 0, NULL, &result) || result.payload[57] || result.payload[58] != 1) return 1;
        }
    }
#ifdef UDP_EXTENDED_PROBES
    {
        static const char reply[] = "HTTP/1.0 200 OK\r\nContent-Type: plex/media-server\r\nName: Test Server\r\nResource-Identifier: test-server-1\r\nPort: 32400\r\nVersion: 1.0-test\r\n\r\n";
        if (udp_probe_classify(32414, (const unsigned char *)reply, sizeof(reply) - 1, cookie) != PROTO_PLEX) return 1;
        {
            static const char xml_reply[] = "HTTP/1.0 200 OK\r\nContent-Type: plex/media-server\r\nName: Test\r\nResource-Identifier: test-1\r\nContent-Length: 18\r\n\r\n<PlexMediaServer/>";
            if (udp_probe_classify(32414, (const unsigned char *)xml_reply, sizeof(xml_reply) - 1, cookie) != PROTO_PLEX) return 1;
            if (!plex_fixture_case(xml_reply, "Length: 18", "Length: 17", 0) ||
                !plex_fixture_case(xml_reply, "Length: 18", "Length: 19", 0) ||
                !plex_fixture_case(xml_reply, "<PlexMediaServer/>", "<OtherMediaRoot/>", 0) ||
                !plex_fixture_case(xml_reply, "<PlexMediaServer/>", "<PlexMediaServer>", 0)) return 1;
        }
        {
            unsigned j;
            char with_body[1024];
            static const char *bodies[] = {
                "<!DOCTYPE PlexMediaServer><PlexMediaServer/>",
                "<PlexMediaServer/><PlexMediaServer/>",
                "<PlexMediaServer/>garbage",
                "<PlexMediaServer xmlns='unrelated'/>",
                "<!DOCTYPE PlexMediaServer [<!ENTITY x SYSTEM 'file:///unavailable'>]><PlexMediaServer>&x;</PlexMediaServer>"
            };
            if (!udp_probe_prepare(32414, cookie, NULL, &result) || result.length != 23 ||
                memcmp(result.payload, "M-SEARCH * HTTP/1.1\r\n\r\n", 23)) return 1;
            for (j = 0; j < sizeof(reply) - 1; j++)
                if (udp_probe_classify(32414, (const unsigned char *)reply, j, cookie) != PROTO_NONE) return 1;
            if (!plex_fixture_case(reply, "Content-Type", "cOnTeNt-TyPe", 1) ||
                !plex_fixture_case(reply, "plex/media-server", "plex/media-player", 0) ||
                !plex_fixture_case(reply, "Name: Test Server", "Name: ", 0) ||
                !plex_fixture_case(reply, "Name: Test Server", "Name: 测试服务器", 1) ||
                !plex_fixture_case(reply, "Name: Test Server", "Name: \xc0\x80", 0) ||
                !plex_fixture_case(reply, "Resource-Identifier: test-server-1", "Other: test-server-1", 0) ||
                !plex_fixture_case(reply, "test-server-1", "bad id", 0) ||
                !plex_fixture_case(reply, "Port: 32400\r\n", "", 1) ||
                !plex_fixture_case(reply, "Port: 32400", "Port: 0", 0) ||
                !plex_fixture_case(reply, "Port: 32400", "Port: 65536", 0) ||
                !plex_fixture_case(reply, "Port: 32400", "Port: 32400x", 0) ||
                !plex_fixture_case(reply, "Version: 1.0-test\r\n", "", 1) ||
                !plex_fixture_case(reply, "Version: 1.0-test", "Name: duplicate", 0) ||
                !plex_fixture_case(reply, "Version: 1.0-test", "Content-Length: 0", 1) ||
                !plex_fixture_case(reply, "Version: 1.0-test", "Content-Length: 42949672960", 0) ||
                !plex_fixture_case(reply, "Version: 1.0-test", "Unknown: ok", 1)) return 1;
            for (j = 0; j < sizeof(bodies) / sizeof(bodies[0]); j++) {
                int n = snprintf(with_body, sizeof(with_body),
                    "HTTP/1.0 200 OK\r\nContent-Type: plex/media-server\r\nName: Test\r\nResource-Identifier: test\r\nContent-Length: %u\r\n\r\n%s",
                    (unsigned)strlen(bodies[j]), bodies[j]);
                if (n < 0 || (unsigned)n >= sizeof(with_body) ||
                    udp_probe_classify(32414, (const unsigned char *)with_body, (unsigned)n, cookie) != PROTO_NONE) return 1;
            }
        }
    }
    {
        struct UdpProbeTarget target;
        unsigned char reply[300] = {0};
        static const unsigned char tower[] =
            "\x05\x00"
            "\x13\x00\x0d\x01\x00\xa0\xde\x97\x6c\xd1\x11\x82\x71\x00\xa0\x24\x42\xdf\x7d\x01\x00\x02\x00\x00\x00"
            "\x13\x00\x0d\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x02\x00\x00\x00"
            "\x01\x00\x0a\x02\x00\x00\x00\x01\x00\x08\x02\x00\x88\x94\x01\x00\x09\x04\x00\xc0\x00\x02\x01";
        memset(&target, 0, sizeof(target));
        target.source.version = target.destination.version = 4;
        target.source.ipv4 = 0xc0000201; target.destination.ipv4 = 0xc6336401;
        target.source_port = 40000;
        if (!udp_probe_runtime_init() || !udp_probe_prepare(34964, cookie, &target, &result)) return 1;
        memcpy(reply, result.payload, 80);
        reply[1] = 2; reply[74] = 156;
        reply[100] = reply[104] = reply[112] = 1;
        reply[134] = 2; reply[140] = 2;
        reply[144] = 'x'; reply[146] = reply[147] = 0xee;
        reply[148] = reply[152] = 75;
        memcpy(reply + 156, tower, sizeof(tower) - 1);
        reply[231] = 0xbf;
        if (udp_probe_classify_target(34964, reply, 236, cookie, &target) != PROTO_PNIO) return 1;
        if (result.length != 156 || result.payload[2] != 8 ||
            result.payload[68] != 2 || result.payload[74] != 76 || result.payload[152] != 1) return 1;
        {
            unsigned j;
            unsigned char changed[300];
            static const unsigned offsets[] = {
                0, 1, 3, 4, 5, 6, 40, 47, 55, 64, 74, 76, 78,
                100, 104, 108, 112, 136, 140, 145, 148, 152,
                156, 158, 160, 161, 177, 179, 181, 183, 185,
                186, 202, 204, 206, 208, 210, 211, 213, 215,
                217, 218, 222, 224, 225, 232
            };
            for (j = 0; j < 236; j++)
                if (udp_probe_classify_target(34964, reply, j, cookie, &target) != PROTO_NONE) return 1;
            for (j = 0; j < sizeof(offsets) / sizeof(offsets[0]); j++) {
                memcpy(changed, reply, sizeof(reply));
                changed[offsets[j]] ^= 0x80;
                if (udp_probe_classify_target(34964, changed, 236, cookie, &target) != PROTO_NONE) return 1;
            }
            if (udp_probe_classify_target(34964, reply, 236, cookie + 1, &target) != PROTO_NONE ||
                udp_probe_classify(34964, reply, 236, cookie) != PROTO_NONE) return 1;
            target.source_port++;
            if (udp_probe_classify_target(34964, reply, 236, cookie, &target) != PROTO_NONE) return 1;
            target.source_port--;
            memcpy(changed, reply, sizeof(reply));
            changed[2] = 0x28; changed[7] = 9; changed[56] = 3; changed[70] = 7; changed[79] = 1;
            if (udp_probe_classify_target(34964, changed, 236, cookie, &target) != PROTO_PNIO) return 1;
            changed[2] = 0x0c;
            if (udp_probe_classify_target(34964, changed, 236, cookie, &target) != PROTO_NONE) return 1;
            memcpy(changed, reply, sizeof(reply));
            memcpy(changed + 161, "\x08\x83\xaf\xe1\x1f\x5d\xc9\x11\x91\xa4\x08\x00\x2b\x14\xa0\xfa", 16);
            changed[177] = 3;
            if (udp_probe_classify_target(34964, changed, 236, cookie, &target) != PROTO_EPM) return 1;
            changed[134] = 0;
            if (udp_probe_classify_target(34964, changed, 236, cookie, &target) != PROTO_NONE) return 1;
        }
    }
    {
        struct UdpProbeTarget target;
        char reply[2048], message_id[46];
        const char *start;
        int length;
        memset(&target, 0, sizeof(target));
        target.source.version = target.destination.version = 4;
        target.source.ipv4 = 0xc0000201; target.destination.ipv4 = 0xc6336401;
        target.source_port = 40000;
        if (!udp_probe_runtime_init() || !udp_probe_prepare(3702, cookie, &target, &result)) return 1;
        start = strstr((const char *)result.payload, "<a:MessageID>");
        if (!start) return 1;
        memcpy(message_id, start + 13, 45); message_id[45] = 0;
        length = snprintf(reply, sizeof(reply),
            "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' "
            "xmlns:a='http://schemas.xmlsoap.org/ws/2004/08/addressing' "
            "xmlns:d='http://schemas.xmlsoap.org/ws/2005/04/discovery' "
            "xmlns:n='http://www.onvif.org/ver10/device/wsdl'>"
            "<s:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action>"
            "<a:MessageID>urn:uuid:01234567-89ab-4cde-8012-3456789abcde</a:MessageID>"
            "<a:RelatesTo>%s</a:RelatesTo>"
            "<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>"
            "<d:AppSequence InstanceId='1' MessageNumber='1'/></s:Header>"
            "<s:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference>"
            "<a:Address>urn:uuid:01234567-89ab-4cde-8012-3456789abcde</a:Address>"
            "</a:EndpointReference><d:Types>n:Device</d:Types>"
            "<d:Scopes>onvif://www.onvif.org/name/test</d:Scopes>"
            "<d:XAddrs>http://192.0.2.1/onvif/device_service</d:XAddrs>"
            "<d:MetadataVersion>1</d:MetadataVersion></d:ProbeMatch>"
            "</d:ProbeMatches></s:Body></s:Envelope>", message_id);
        if (length < 0 || (unsigned)length >= sizeof(reply) ||
            udp_probe_classify_target(3702, (const unsigned char *)reply, (unsigned)length, cookie, &target) != PROTO_ONVIF) return 1;
        if (!onvif_fixture_case(reply,
                "<d:Types>n:Device</d:Types><d:Scopes>onvif://www.onvif.org/name/test</d:Scopes>",
                "<d:Scopes>onvif://www.onvif.org/name/test</d:Scopes><d:Types>n:Device</d:Types>",
                0, cookie, &target)) return 1;
        if (!onvif_fixture_case(reply, "<a:Action>",
                "<a:Action s:role='http://www.w3.org/2003/05/soap-envelope/role/none'>", 0, cookie, &target)) return 1;
        {
            static const struct {const char *needle, *replacement; int valid;} cases[] = {
                {"xmlns:n='http://www.onvif.org/ver10/device/wsdl'", "xmlns:n='urn:other'", 0},
                {"<d:Types>n:Device</d:Types>", "<d:Types xmlns='http://www.onvif.org/ver10/device/wsdl'>Device</d:Types>", 1},
                {"<d:Types>n:Device</d:Types>", "<d:Types xmlns:q='http://www.onvif.org/ver10/device/wsdl'>q:Device</d:Types>", 1},
                {"<d:Types>n:Device</d:Types>", "<d:Types xmlns:n='urn:other'>n:Device</d:Types>", 0},
                {"<d:Types>n:Device</d:Types>", "<d:Types>z:Device</d:Types>", 0},
                {"<d:Types>n:Device</d:Types>", "<d:Types>n:Printer</d:Types>", 0},
                {"<d:Types>n:Device</d:Types>", "<d:Types>n:<x/>Device</d:Types>", 0},
                {"<d:Types>n:Device</d:Types>", "<d:Types>n:Printer n:Device</d:Types>", 1},
                {"<d:AppSequence InstanceId='1' MessageNumber='1'/>", "", 0},
                {"<d:AppSequence InstanceId='1' MessageNumber='1'/>", "<d:AppSequence InstanceId='1'/>", 0},
                {"InstanceId='1'", "InstanceId='4294967295'", 1},
                {"InstanceId='1'", "InstanceId='4294967296'", 0},
                {"MessageNumber='1'", "MessageNumber=' +1 '", 1},
                {"MessageNumber='1'", "MessageNumber='-1'", 0},
                {"<d:MetadataVersion>1", "<d:MetadataVersion>4294967296", 0},
                {"<a:RelatesTo>", "<a:RelatesTo RelationshipType='a:Reply'>", 1},
                {"<a:RelatesTo>", "<a:RelatesTo RelationshipType='d:Suppression'>urn:other</a:RelatesTo><a:RelatesTo>", 1},
                {"<a:RelatesTo>", "<a:RelatesTo RelationshipType='d:Suppression'>", 0},
                {"<a:RelatesTo>", "<a:RelatesTo>urn:other</a:RelatesTo><a:RelatesTo>", 0},
                {"<s:Header>", "<s:Header><x:Ignored xmlns:x='urn:extra' s:mustUnderstand='false'><x:Text>optional</x:Text></x:Ignored>", 1},
                {"<s:Header>", "<s:Header><x:Ignored xmlns:x='urn:extra' s:mustUnderstand='true'/>", 0},
                {"<s:Header>", "<s:Header><x:Ignored xmlns:x='urn:extra' xmlns:n='urn:wrong'/>", 1},
                {"<a:Action>", "<a:Action s:role='http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver'>", 1},
                {"<s:Header>", "<s:Header><a:Action>urn:wrong</a:Action>", 0},
                {"<d:XAddrs>http://192.0.2.1/onvif/device_service</d:XAddrs>", "", 0},
                {"http://192.0.2.1/onvif/device_service", "https://[2001:db8::1]:443/device?a=1&amp;b=2", 1},
                {"http://192.0.2.1/onvif/device_service", "ftp://192.0.2.1/device", 0},
                {"http://192.0.2.1/onvif/device_service", "http://host:65536/device", 0},
                {"http://192.0.2.1/onvif/device_service", "http://host/%GG", 0},
                {"http://192.0.2.1/onvif/device_service", "http://user@host/device", 0},
                {"http://192.0.2.1/onvif/device_service", "http://host/device http://other/device", 1},
                {"<s:Envelope", "<!DOCTYPE Envelope><s:Envelope", 0},
                {"<s:Envelope", "<!DOCTYPE Envelope SYSTEM 'file:///nonexistent'><s:Envelope", 0},
                {"<s:Envelope", "<?xml version='1.0' encoding='ISO-8859-1'?><s:Envelope", 0},
                {"</s:Envelope>", "</s:Envelope><!--end-->", 1},
                {"</s:Envelope>", "</s:Envelope>garbage", 0},
                {"<d:MetadataVersion>1</d:MetadataVersion>", "<d:MetadataVersion>1</d:MetadataVersion><d:MetadataVersion>1</d:MetadataVersion>", 0},
                {"<a:EndpointReference>", "<a:EndpointReference><a:Address>urn:other</a:Address>", 0}
            };
            struct UdpProbeTarget other = target;
            for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
                if (!onvif_fixture_case(reply, cases[i].needle, cases[i].replacement, cases[i].valid, cookie, &target)) {
                    fprintf(stderr, "udp: XML fixture %u failed\n", i); return 1;
                }
            for (i = 0; i < (unsigned)length; i++)
                if (udp_probe_classify_target(3702, (const unsigned char *)reply, i, cookie, &target) != PROTO_NONE) return 1;
            other.destination.ipv4++;
            if (udp_probe_classify_target(3702, (const unsigned char *)reply, (unsigned)length, cookie, &other) != PROTO_NONE ||
                udp_probe_classify_target(3702, (const unsigned char *)reply, (unsigned)length, cookie ^ 1, &target) != PROTO_NONE ||
                udp_probe_classify(3702, (const unsigned char *)reply, (unsigned)length, cookie) != PROTO_NONE) return 1;
            {
                char duplicate[4096], nested[512];
                const char *begin = strstr(reply, "<d:ProbeMatch>");
                const char *end = strstr(reply, "</d:ProbeMatch>");
                size_t size, used = 0;
                if (!begin || !end) return 1;
                size = (size_t)(end + strlen("</d:ProbeMatch>") - begin);
                if (2 * size + 1 > sizeof(duplicate)) return 1;
                memcpy(duplicate, begin, size); memcpy(duplicate + size, begin, size); duplicate[2 * size] = 0;
                if (!onvif_fixture_case(reply, "</d:ProbeMatches>", duplicate, 0, cookie, &target)) return 1;
                memcpy(duplicate, begin, size); duplicate[size] = 0;
                memcpy(duplicate + size, "</d:ProbeMatches>", sizeof("</d:ProbeMatches>"));
                if (!onvif_fixture_case(reply, "</d:ProbeMatches>", duplicate, 1, cookie, &target)) return 1;
                memcpy(nested, "<s:Header>", 10); used = 10;
                for (i = 0; i < 17; i++) { memcpy(nested + used, "<x>", 3); used += 3; }
                for (i = 0; i < 17; i++) { memcpy(nested + used, "</x>", 4); used += 4; }
                nested[used] = 0;
                if (!onvif_fixture_case(reply, "<s:Header>", nested, 0, cookie, &target)) return 1;
            }
        }
    }
    {
        struct UdpProbeTarget target;
        unsigned char reply[64] = {0};
        memset(&target, 0, sizeof(target));
        target.source.version = target.destination.version = 4;
        target.source.ipv4 = 0xc0000201;
        target.destination.ipv4 = 0xc6336401;
        target.source_port = 40000;
        if (!udp_probe_runtime_init() || !udp_probe_prepare(3478, cookie, &target, &result)) return 1;
        memcpy(reply, result.payload, 20);
        reply[0] = 1; reply[3] = 12;
        memcpy(reply + 20, "\x00\x20\x00\x08\x00\x01\xa1\x47\xe1\x12\xa6\x43", 12);
        if (udp_probe_classify_target(3478, reply, 32, cookie, &target) != PROTO_STUN) return 1;
        {
            struct UdpProbeTarget other = target;
            unsigned char changed[96], transaction[12];
            if (result.length != 20 || memcmp(result.payload, "\x00\x01\x00\x00\x21\x12\xa4\x42", 8)) return 1;
            memcpy(transaction, result.payload + 8, 12);
            if (udp_probe_classify(3478, reply, 32, cookie) != PROTO_NONE ||
                udp_probe_classify_target(3478, reply, 32, cookie ^ 1, &target) != PROTO_NONE ||
                udp_probe_classify_target(3478, result.payload, 20, cookie, &target) != PROTO_NONE) return 1;
            for (i = 0; i < 32; i++)
                if (udp_probe_classify_target(3478, reply, i, cookie, &target) != PROTO_NONE) return 1;
            for (i = 8; i < 20; i++) {
                memcpy(changed, reply, 32); changed[i] ^= 1;
                if (udp_probe_classify_target(3478, changed, 32, cookie, &target) != PROTO_NONE) return 1;
            }
            other.destination.ipv4++;
            if (udp_probe_classify_target(3478, reply, 32, cookie, &other) != PROTO_NONE ||
                !udp_probe_prepare(3478, cookie, &other, &result) || !memcmp(transaction, result.payload + 8, 12)) return 1;
            other = target; other.source.ipv4++;
            if (udp_probe_classify_target(3478, reply, 32, cookie, &other) != PROTO_NONE) return 1;
            other = target; other.source_port++;
            if (udp_probe_classify_target(3478, reply, 32, cookie, &other) != PROTO_NONE) return 1;
            other.source.version = other.destination.version = 6;
            other.source.ipv6.hi = other.destination.ipv6.hi = UINT64_C(0x20010db800000000);
            other.source.ipv6.lo = 1; other.destination.ipv6.lo = 2;
            if (!udp_probe_prepare(3478, cookie, &other, &result) || !memcmp(transaction, result.payload + 8, 12)) return 1;
            memcpy(changed, reply, 32); memcpy(changed + 8, result.payload + 8, 12);
            if (udp_probe_classify_target(3478, changed, 32, cookie, &other) != PROTO_STUN) return 1;
            if (udp_probe_prepare(3478, cookie, NULL, &result)) return 1;
            other.source.version = 0;
            if (udp_probe_prepare(3478, cookie, &other, &result)) return 1;
            memcpy(changed, reply, 32); changed[24] = 255;
            if (udp_probe_classify_target(3478, changed, 32, cookie, &target) != PROTO_STUN) return 1;
            changed[25] = 3;
            if (udp_probe_classify_target(3478, changed, 32, cookie, &target) != PROTO_NONE) return 1;
            memcpy(changed, reply, 32); changed[3] = 36;
            memcpy(changed + 32, "\x00\x08\x00\x14", 4); memset(changed + 36, 0, 20);
            if (udp_probe_classify_target(3478, changed, 56, cookie, &target) != PROTO_NONE) return 1;
            memcpy(changed, reply, 32); changed[3] = 20;
            memcpy(changed + 32, "\xff\xff\x00\x01\x58\xaa\xbb\xcc", 8);
            if (udp_probe_classify_target(3478, changed, 40, cookie, &target) != PROTO_STUN) return 1;
            changed[32] = 0x7f;
            if (udp_probe_classify_target(3478, changed, 40, cookie, &target) != PROTO_NONE) return 1;
            memcpy(changed, reply, 32); changed[3] = 24;
            memcpy(changed + 32, reply + 20, 12); changed[37] = 3;
            if (udp_probe_classify_target(3478, changed, 44, cookie, &target) != PROTO_STUN) return 1;
            changed[25] = 3; changed[37] = 1;
            if (udp_probe_classify_target(3478, changed, 44, cookie, &target) != PROTO_NONE) return 1;
            memcpy(changed, reply, 32); changed[3] = 24; changed[23] = 20; changed[25] = 2;
            memset(changed + 32, 0, 12);
            if (udp_probe_classify_target(3478, changed, 44, cookie, &target) != PROTO_STUN) return 1;
            changed[23] = 19;
            if (udp_probe_classify_target(3478, changed, 44, cookie, &target) != PROTO_NONE) return 1;
        }
    }
    {
        unsigned char reply[256] = {0};
        static const unsigned char sa[] =
            "\x22\x00\x00\x30\x00\x00\x00\x2c\x01\x01\x00\x04"
            "\x03\x00\x00\x0c\x01\x00\x00\x0c\x80\x0e\x00\x80"
            "\x03\x00\x00\x08\x02\x00\x00\x05"
            "\x03\x00\x00\x08\x03\x00\x00\x0c"
            "\x00\x00\x00\x08\x04\x00\x00\x1f";
        if (!udp_probe_runtime_init() || !udp_probe_prepare(500, cookie, NULL, &result)) return 1;
        memcpy(reply, result.payload, 8);
        reply[8] = 1;
        memcpy(reply + 16, "\x21\x20\x22\x20\x00\x00\x00\x00\x00\x00\x00\x98", 12);
        memcpy(reply + 28, sa, sizeof(sa) - 1);
        memcpy(reply + 76, "\x28\x00\x00\x28\x00\x1f\x00\x00", 8);
        /* RFC7748's base point is a valid peer public input. */
        reply[84] = 9;
        reply[119] = 36;
        memset(reply + 120, 0x71, 32);
        if (udp_probe_classify(500, reply, 152, cookie) != PROTO_IKEV2) return 1;
        {
            unsigned char changed[512];
            memcpy(changed, reply, 152);
            changed[116] = 41; changed[27] = 180;
            memset(changed + 152, 0, 28);
            changed[155] = 28;
            changed[158] = 0x40; changed[159] = 4;
            memset(changed + 160, 0x42, 20);
            if (udp_probe_classify(500, changed, 180, cookie) != PROTO_IKEV2) return 1;
            changed[159] = 5;
            if (udp_probe_classify(500, changed, 180, cookie) != PROTO_IKEV2) return 1;
            changed[159] = 6;
            if (udp_probe_classify(500, changed, 180, cookie) != PROTO_NONE) return 1;
            changed[159] = 4; changed[157] = 8;
            if (udp_probe_classify(500, changed, 180, cookie) != PROTO_NONE) return 1;
            if (result.length != 152 || memcmp(result.payload + 28, sa, sizeof(sa) - 1) ||
                memcmp(result.payload + 16, "\x21\x20\x22\x08\x00\x00\x00\x00\x00\x00\x00\x98", 12)) return 1;
            if (udp_probe_classify(500, result.payload, result.length, cookie) != PROTO_NONE ||
                udp_probe_classify(500, reply, 152, cookie ^ 1) != PROTO_NONE) return 1;
            for (i = 0; i < 152; i++)
                if (udp_probe_classify(500, reply, i, cookie) != PROTO_NONE) return 1;
            {
                static const unsigned offsets[] = {0, 16, 17, 18, 20, 24, 27, 30, 32, 34, 36, 37, 38, 39, 40, 42, 44, 47, 49, 51, 55, 59, 63, 67, 71, 75, 78, 81, 118, 119};
                for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
                    memcpy(changed, reply, 152);
                    changed[offsets[i]] ^= 0x40;
                    if (udp_probe_classify(500, changed, 152, cookie) != PROTO_NONE) return 1;
                }
            }
            memcpy(changed, reply, 152);
            memset(changed + 84, 0, 32);
            if (udp_probe_classify(500, changed, 152, cookie) != PROTO_NONE) return 1;
            changed[84] = 1;
            if (udp_probe_classify(500, changed, 152, cookie) != PROTO_NONE) return 1;
            changed[84] = 9; changed[115] = 0x80;
            if (udp_probe_classify(500, changed, 152, cookie) != PROTO_IKEV2) return 1;
            memcpy(changed, reply, 152);
            changed[19] |= 8;
            if (udp_probe_classify(500, changed, 152, cookie) != PROTO_NONE) return 1;
            changed[19] = 0xa0;
            if (udp_probe_classify(500, changed, 152, cookie) != PROTO_IKEV2) return 1;
            memcpy(changed, reply, 152);
            changed[27] = 136; changed[119] = 20;
            if (udp_probe_classify(500, changed, 136, cookie) != PROTO_IKEV2) return 1;
            changed[27] = 135; changed[119] = 19;
            if (udp_probe_classify(500, changed, 135, cookie) != PROTO_NONE) return 1;
            memcpy(changed, reply, 152);
            changed[24] = 0; changed[25] = 0; changed[26] = 1; changed[27] = 120;
            changed[118] = 1; changed[119] = 4;
            memset(changed + 120, 0x71, 256);
            if (udp_probe_classify(500, changed, 376, cookie) != PROTO_IKEV2) return 1;
            changed[27] = 121; changed[119] = 5;
            if (udp_probe_classify(500, changed, 377, cookie) != PROTO_NONE) return 1;
            memcpy(changed, reply, 152);
            changed[116] = 250; changed[27] = 156;
            memcpy(changed + 152, "\x00\x00\x00\x04", 4);
            if (udp_probe_classify(500, changed, 156, cookie) != PROTO_IKEV2) return 1;
            changed[153] = 0x80;
            if (udp_probe_classify(500, changed, 156, cookie) != PROTO_NONE) return 1;
            changed[153] = 0; changed[116] = 40;
            if (udp_probe_classify(500, changed, 156, cookie) != PROTO_NONE) return 1;
            memcpy(changed, reply, 152);
            memcpy(changed + 52, reply + 60, 8);
            if (udp_probe_classify(500, changed, 152, cookie) != PROTO_NONE) return 1;
            memcpy(changed + 60, reply + 52, 8);
            if (udp_probe_classify(500, changed, 152, cookie) != PROTO_IKEV2) return 1;
        }
    }
    {
        unsigned char reply[128] = {0};
        static const unsigned char sa[] =
            "\x00\x00\x00\x30\x00\x00\x00\x01\x00\x00\x00\x01"
            "\x00\x00\x00\x24\x01\x01\x00\x01"
            "\x00\x00\x00\x1c\x01\x01\x00\x00"
            "\x80\x01\x00\x07\x80\x02\x00\x02\x80\x03\x00\x03"
            "\x80\x04\x00\x0e\x80\x0e\x00\x80";
        if (!udp_probe_runtime_init() || !udp_probe_prepare(4500, cookie, NULL, &result)) return 1;
        memcpy(reply + 4, result.payload + 4, 8);
        reply[12] = 1;
        memcpy(reply + 20, "\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x4c", 12);
        memcpy(reply + 32, sa, sizeof(sa) - 1);
        if (udp_probe_classify(4500, reply, 80, cookie) != PROTO_IKEV1) return 1;
        {
            unsigned char changed[128];
            static const unsigned offsets[] = {0, 4, 20, 21, 22, 24, 28, 31, 34, 36, 40, 44, 46, 48, 49, 50, 51, 52, 54, 56, 57, 60, 63, 67, 71, 75, 79};
            if (result.length != 100 || memcmp(result.payload, "\x00\x00\x00\x00", 4) ||
                memcmp(result.payload + 20, "\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x60", 12) ||
                memcmp(result.payload + 33, sa + 1, sizeof(sa) - 2) || result.payload[32] != 13) return 1;
            if (udp_probe_classify(4500, result.payload, result.length, cookie) != PROTO_NONE ||
                udp_probe_classify(4500, reply, 80, cookie ^ 1) != PROTO_NONE) return 1;
            for (i = 0; i < 80; i++)
                if (udp_probe_classify(4500, reply, i, cookie) != PROTO_NONE) return 1;
            for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
                memcpy(changed, reply, 80);
                changed[offsets[i]] ^= 0x40;
                if (udp_probe_classify(4500, changed, 80, cookie) != PROTO_NONE) return 1;
            }
            memcpy(changed, reply, 80);
            changed[23] = 1;
            if (udp_probe_classify(4500, changed, 80, cookie) != PROTO_NONE) return 1;
            changed[23] = 0x80;
            if (udp_probe_classify(4500, changed, 80, cookie) != PROTO_IKEV1) return 1;
            memcpy(changed, reply, 80);
            changed[32] = 13; changed[31] = 96;
            memcpy(changed + 80, result.payload + 80, 20);
            if (udp_probe_classify(4500, changed, 100, cookie) != PROTO_IKEV1) return 1;
            changed[82] = 1;
            if (udp_probe_classify(4500, changed, 100, cookie) != PROTO_NONE) return 1;
            memcpy(changed, reply, 80);
            memcpy(changed + 60, reply + 76, 4);
            memcpy(changed + 76, reply + 60, 4);
            if (udp_probe_classify(4500, changed, 80, cookie) != PROTO_IKEV1) return 1;
            memcpy(changed + 60, changed + 64, 4);
            if (udp_probe_classify(4500, changed, 80, cookie) != PROTO_NONE) return 1;
            memcpy(changed, reply, 80);
            changed[60] = 0;
            if (udp_probe_classify(4500, changed, 80, cookie) != PROTO_NONE) return 1;
            changed[31] = 77; changed[80] = 0;
            if (udp_probe_classify(4500, changed, 81, cookie) != PROTO_NONE) return 1;
            memcpy(changed, reply, 32);
            changed[20] = 13; changed[31] = 96;
            memcpy(changed + 32, result.payload + 80, 20);
            changed[32] = 1;
            memcpy(changed + 52, reply + 32, 48);
            if (udp_probe_classify(4500, changed, 100, cookie) != PROTO_NONE) return 1;
        }
    }
    {
        static const unsigned char reply[] =
            "\x16\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10"
            "\x03\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04\xfe\xff\x01\x01";
        if (udp_probe_classify(3391, reply, sizeof(reply) - 1, cookie) != PROTO_DTLS) return 1;
        {
            unsigned char flight[128] = {0};
            /* A ServerHello selecting the offered RSA suite needs Certificate
             * before ServerHelloDone in the same first flight. */
            memcpy(flight, "\x16\xfe\xfd", 3);
            flight[12] = 62;
            flight[13] = 2;
            flight[16] = flight[24] = 38;
            flight[25] = 254; flight[26] = 253;
            flight[61] = 47;
            flight[63] = 14; flight[68] = 1;
            if (udp_probe_classify(3391, flight, 75, cookie) != PROTO_NONE) return 1;
            /* The standalone first ServerHello is a complete message. */
            flight[12] = 50;
            if (udp_probe_classify(3391, flight, 63, cookie) != PROTO_DTLS) return 1;
            for (i = 0; i < 63; i++)
                if (udp_probe_classify(3391, flight, i, cookie) != PROTO_NONE) return 1;
            flight[61] = 48;
            if (udp_probe_classify(3391, flight, 63, cookie) != PROTO_NONE) return 1;
            flight[61] = 47;
            flight[59] = 33;
            if (udp_probe_classify(3391, flight, 63, cookie) != PROTO_NONE) return 1;
            flight[59] = 0;
            /* Certificate list framing, followed by ServerHelloDone. */
            memset(flight + 63, 0, 65);
            flight[12] = 81;
            flight[63] = 11; flight[66] = 7; flight[68] = 1; flight[74] = 7;
            flight[77] = 4; flight[80] = 1; flight[81] = 0x30;
            flight[82] = 14; flight[87] = 2;
            if (udp_probe_classify(3391, flight, 94, cookie) != PROTO_DTLS) return 1;
            flight[80] = 2;
            if (udp_probe_classify(3391, flight, 94, cookie) != PROTO_NONE) return 1;
            flight[80] = 1;
            /* The same messages split across two consecutive records. */
            memmove(flight + 76, flight + 63, 31);
            memcpy(flight + 63, flight, 13);
            flight[12] = 50; flight[73] = 1; flight[75] = 31;
            if (udp_probe_classify(3391, flight, 107, cookie) != PROTO_DTLS) return 1;
            flight[73] = 2;
            if (udp_probe_classify(3391, flight, 107, cookie) != PROTO_NONE) return 1;
        }
        {
            static const unsigned offsets[] = {0, 1, 2, 3, 4, 5, 10, 12, 13, 16, 18, 21, 24, 25, 26, 27};
            unsigned char changed[sizeof(reply)];
            if (!udp_probe_runtime_init() || !udp_probe_prepare(3391, cookie, NULL, &result) ||
                result.length != 67 ||
                memcmp(result.payload, "\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x36\x01\x00\x00\x2a\x00\x00\x00\x00\x00\x00\x00\x2a\xfe\xfd", 27) ||
                memcmp(result.payload + 59, "\x00\x00\x00\x02\x00\x2f\x01\x00", 8)) return 1;
            if (udp_probe_classify(3391, result.payload, result.length, cookie) != PROTO_NONE) return 1;
            for (i = 0; i < sizeof(reply) - 1; i++)
                if (udp_probe_classify(3391, reply, i, cookie) != PROTO_NONE) return 1;
            for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
                memcpy(changed, reply, sizeof(reply));
                changed[offsets[i]] ^= 0x40;
                if (udp_probe_classify(3391, changed, sizeof(reply) - 1, cookie) != PROTO_NONE) return 1;
            }
            memcpy(changed, reply, sizeof(reply));
            changed[2] = changed[26] = 253;
            if (udp_probe_classify(3391, changed, sizeof(reply) - 1, cookie) != PROTO_DTLS) return 1;
            if (udp_probe_classify(3391, changed, sizeof(reply), cookie) != PROTO_NONE) return 1;
            changed[27] = 0;
            if (udp_probe_classify(3391, changed, sizeof(reply) - 1, cookie) != PROTO_NONE) return 1;
        }
    }
    {
        static const unsigned char reply[] = "<hudson><version>2.218</version></hudson>";
        if (udp_probe_classify(33848, reply, sizeof(reply) - 1, cookie) != PROTO_JENKINS) return 1;
        {
            static const struct {const char *text; int valid;} cases[] = {
                {"<?xml version='1.0' encoding='UTF-8'?><hudson><version>2.218-SNAPSHOT</version></hudson>", 1},
                {"<hudson><version>2<![CDATA[.218]]></version><url>http://example.test/?a=1&amp;b=2</url><slave-port>65535</slave-port><server-id>x</server-id><p:plugin xmlns:p='urn:plugin'><version>other</version></p:plugin></hudson><!--done-->", 1},
                {"<hudson><version>&#50;.218</version></hudson>", 1},
                {"<hudson><version>2</version><version>3</version></hudson>", 0},
                {"<hudson><version>2</version><slave-port>0</slave-port></hudson>", 0},
                {"<hudson><version>2</version><slave-port>65536</slave-port></hudson>", 0},
                {"<hudson><version>2</version><slave-port>-1</slave-port></hudson>", 0},
                {"<hudson><version>2</version><slave-port>1</slave-port><slave-port>2</slave-port></hudson>", 0},
                {"<hudson><version>2<x/>.218</version></hudson>", 0},
                {"<hudson><plugin><version>2</version></plugin></hudson>", 0},
                {"<hudson xmlns='urn:other'><version>2</version></hudson>", 0},
                {"<other><version>2</version></other>", 0},
                {"<hudson><version> </version></hudson>", 0},
                {"<hudson><version>2</version></hudson><hudson/>", 0},
                {"<hudson><version>2</version></hudson>garbage", 0},
                {"<hudson>garbage<version>2</version></hudson>", 0},
                {"<hudson><version>\xc0\xaf</version></hudson>", 0},
                {"<!DOCTYPE hudson><hudson><version>2</version></hudson>", 0},
                {"<!DOCTYPE hudson [<!ENTITY v '2'>]><hudson><version>&v;</version></hudson>", 0},
                {"<!DOCTYPE hudson SYSTEM 'file:///nonexistent'><hudson><version>2</version></hudson>", 0},
                {"<?xml version='1.0' encoding='ISO-8859-1'?><hudson><version>2</version></hudson>", 0}
            };
            unsigned char nested[300];
            unsigned offset = 0;
            if (!udp_probe_prepare(33848, cookie, NULL, &result) || result.length != 1 || result.payload[0]) return 1;
            for (i = 0; i < sizeof(reply) - 1; i++)
                if (udp_probe_classify(33848, reply, i, cookie) != PROTO_NONE) return 1;
            if (udp_probe_classify(33848, reply, sizeof(reply), cookie) != PROTO_NONE) return 1;
            for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
                if ((udp_probe_classify(33848, (const unsigned char *)cases[i].text,
                     (unsigned)strlen(cases[i].text), cookie) == PROTO_JENKINS) != cases[i].valid) {
                    fprintf(stderr, "Jenkins XML case %u failed\n", i);
                    return 1;
                }
            memcpy(nested, "<hudson><version>2</version>", 28);
            offset = 28;
            for (i = 0; i < 17; i++) { memcpy(nested + offset, "<x>", 3); offset += 3; }
            for (i = 0; i < 17; i++) { memcpy(nested + offset, "</x>", 4); offset += 4; }
            memcpy(nested + offset, "</hudson>", 9);
            offset += 9;
            if (udp_probe_classify(33848, nested, offset, cookie) != PROTO_NONE) return 1;
        }
    }
    {
        static const unsigned char reply[] = "d1:rd2:id20:abcdefghij0123456789e1:t4:\x89\xab\xcd\xef" "1:y1:re";
        if (udp_probe_classify(6881, reply, sizeof(reply) - 1, cookie) != PROTO_DHT) return 1;
        {
            static const struct {const char *text; int valid;} cases[] = {
                {"d1:eli201e5:errore1:t4:abcd1:y1:ee", 1},
                {"d1:eli204e0:e1:t4:abcd1:y1:ee", 1},
                {"d1:eli205e5:errore1:t4:abcd1:y1:ee", 0},
                {"d1:eli0201e5:errore1:t4:abcd1:y1:ee", 0},
                {"d1:eli201e5:errori1ee1:t4:abcd1:y1:ee", 0},
                {"d1:eli9223372036854775808e5:errore1:t4:abcd1:y1:ee", 0},
                {"d1:rd2:id20:abcdefghij0123456789e1:t4:abcd1:y1:r1:zi-9223372036854775808ee", 1},
                {"d1:rd2:id20:abcdefghij0123456789e1:t4:abcd1:y1:r1:zi-0ee", 0},
                {"d1:rd2:id20:abcdefghij0123456789e1:t4:abcd1:t4:abcd1:y1:re", 0},
                {"d1:rd2:id20:abcdefghij0123456789e1:t4:abcd1:y1:q e", 0},
                {"d1:rd2:id19:abcdefghij012345678e1:t4:abcd1:y1:re", 0},
                {"d1:rd2:id21:abcdefghij01234567890e1:t4:abcd1:y1:re", 0},
                {"d1:rd2:id20:abcdefghij0123456789e1:t4:abcd1:y1:r1:z999999999999999999999:x e", 0},
                {"d1:rd2:id20:abcdefghij0123456789e1:t4:abcd1:y1:r1:zlllllllllleeeeeeeeeeee", 0},
                {"d1:rd2:id20:abcdefghij0123456789e1:y1:r1:t4:abcde", 0},
                {"d1:rd2:id20:abcdefghij0123456789e1:t04:abcd1:y1:re", 0}
            };
            struct UdpPreparedProbe second;
            unsigned char altered[sizeof(reply)];
            for (i = 0; i < sizeof(reply) - 1; i++)
                if (udp_probe_classify(6881, reply, i, cookie) != PROTO_NONE) return 1;
            if (udp_probe_classify(6881, reply, sizeof(reply), cookie) != PROTO_NONE ||
                udp_probe_classify(6881, reply, sizeof(reply) - 1, cookie ^ 1) != PROTO_NONE) return 1;
            for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
                if ((udp_probe_classify(6881, (const unsigned char *)cases[i].text,
                     (unsigned)strlen(cases[i].text), 0x61626364) == PROTO_DHT) != cases[i].valid) {
                    fprintf(stderr, "DHT response case %u failed\n", i);
                    return 1;
                }
            if (!udp_probe_runtime_init() || !udp_probe_prepare(6881, cookie, NULL, &result) ||
                result.length != 58 || memcmp(result.payload, "d1:ad2:id20:", 12) ||
                memcmp(result.payload + 32, "e1:q4:ping1:t4:\x89\xab\xcd\xef" "1:y1:qe", 26)) {
                fprintf(stderr, "DHT request encoding failed (length %u)\n", result.length);
                return 1;
            }
            if (!udp_probe_prepare(6881, cookie ^ 1, NULL, &second) ||
                memcmp(result.payload + 12, second.payload + 12, 20)) return 1;
            memcpy(altered, reply, sizeof(reply));
            /* A transaction may contain zero bytes, unlike a C string. */
            {
                unsigned offset = (unsigned)(strstr((const char *)reply, "1:t4:") - (const char *)reply) + 5;
                memset(altered + offset, 0, 4);
                if (udp_probe_classify(6881, altered, sizeof(reply) - 1, 0) != PROTO_DHT) return 1;
            }
        }
    }
    {
        unsigned char reply[26] = {0x40, 1, 2, 3, 4, 5, 6, 7, 8, 1};
        if (!udp_probe_runtime_init()) return 1;
        if (!udp_probe_prepare(1194, cookie, NULL, &result) || result.length != 14) return 1;
        memcpy(reply + 14, result.payload + 1, 8);
        if (udp_probe_classify(1194, reply, sizeof(reply), cookie) != PROTO_OPENVPN) return 1;
        if (result.payload[0] != 0x38 || memcmp(result.payload + 9, "\x00\x00\x00\x00\x00", 5)) return 1;
        for (i = 0; i < sizeof(reply); i++)
            if (udp_probe_classify(1194, reply, i, cookie) != PROTO_NONE) return 1;
        if (udp_probe_classify(1194, reply, sizeof(reply), cookie ^ 1) != PROTO_NONE ||
            udp_probe_classify(1194, result.payload, result.length, cookie) != PROTO_NONE) return 1;
        for (i = 0; i < sizeof(reply); i++) {
            unsigned char saved = reply[i];
            if (i > 0 && i < 9) continue;
            reply[i] ^= 1;
            if (udp_probe_classify(1194, reply, sizeof(reply), cookie) != PROTO_NONE) return 1;
            reply[i] = saved;
        }
        memset(reply + 1, 0, 8);
        if (udp_probe_classify(1194, reply, sizeof(reply), cookie) != PROTO_NONE) return 1;
        if (!udp_probe_prepare(1194, cookie, NULL, &result) ||
            memcmp(result.payload + 1, reply + 14, 8)) return 1;
    }
#endif
    {
        static const unsigned char reply[] =
            "\x81\x0a\x00\x14\x01\x00\x10\x00\xc4\x02\x00\x00\x7b\x22\x05\xc4\x91\x03\x21\x0f";
        if (udp_probe_classify(47808, reply, sizeof(reply) - 1, cookie) != PROTO_BACNET) return 1;
        {
            unsigned char altered[40];
            static const unsigned offsets[] = {0, 1, 3, 4, 6, 7, 8, 9, 13, 16, 18};
            if (!udp_probe_prepare(47808, cookie, NULL, &result) || result.length != 8 ||
                memcmp(result.payload, "\x81\x0a\x00\x08\x01\x00\x10\x08", 8)) return 1;
            for (i = 0; i < sizeof(reply) - 1; i++)
                if (udp_probe_classify(47808, reply, i, cookie) != PROTO_NONE) return 1;
            if (udp_probe_classify(47808, reply, sizeof(reply), cookie) != PROTO_NONE) return 1;
            for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
                memcpy(altered, reply, 20);
                altered[offsets[i]] ^= 1;
                if (udp_probe_classify(47808, altered, 20, cookie) != PROTO_NONE) return 1;
            }
            memcpy(altered, reply, 20);
            altered[5] = 3;
            if (udp_probe_classify(47808, altered, 20, cookie) != PROTO_BACNET) return 1;
            altered[5] = 128;
            if (udp_probe_classify(47808, altered, 20, cookie) != PROTO_NONE) return 1;
            altered[5] = 0;
            altered[17] = 4;
            if (udp_probe_classify(47808, altered, 20, cookie) != PROTO_NONE) return 1;
            memcpy(altered, reply, 20);
            altered[18] = 0x23;
            memcpy(altered + 19, "\x01\x00\x00", 3);
            altered[3] = 22;
            if (udp_probe_classify(47808, altered, 22, cookie) != PROTO_NONE) return 1;
            altered[19] = 0;
            altered[20] = 255;
            altered[21] = 255;
            if (udp_probe_classify(47808, altered, 22, cookie) != PROTO_BACNET) return 1;
            memcpy(altered, reply, 6);
            altered[3] = 28;
            altered[5] = 40;
            memcpy(altered + 6, "\xff\xff\x00\x00\x01\x01\x07\xff", 8);
            memcpy(altered + 14, reply + 6, 14);
            if (udp_probe_classify(47808, altered, 28, cookie) != PROTO_BACNET) return 1;
            altered[11] = 20;
            if (udp_probe_classify(47808, altered, 28, cookie) != PROTO_NONE) return 1;
            altered[11] = 0;
            if (udp_probe_classify(47808, altered, 28, cookie) != PROTO_NONE) return 1;
        }
    }
    {
        static const unsigned char reply[] =
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\n"
            "LOCATION: http://192.0.2.1/device.xml\r\nSERVER: Test/1 UPnP/1.0 Product/1\r\n"
            "ST: upnp:rootdevice\r\nUSN: uuid:12345678-1234-1234-1234-123456789abc::upnp:rootdevice\r\n\r\n";
        if (udp_probe_classify(1900, reply, sizeof(reply) - 1, cookie) != PROTO_SSDP) return 1;
        {
            static const struct {const char *field; const char *line; int valid;} cases[] = {
                {"CACHE-CONTROL:", "cache-control: max-age=1, private, x=\"a,b\"", 1},
                {"CACHE-CONTROL:", "CACHE-CONTROL: max-age=1, max-age=2", 0},
                {"CACHE-CONTROL:", "CACHE-CONTROL: max-age=-1", 0},
                {"CACHE-CONTROL:", "CACHE-CONTROL: max-age=4294967296", 0},
                {"CACHE-CONTROL:", "CACHE-CONTROL: private", 0},
                {"EXT:", "OTHER:", 0},
                {"EXT:", "EXT: text", 0},
                {"LOCATION:", "LOCATION: HTTP://example.test/device.xml", 1},
                {"LOCATION:", "LOCATION: http://[2001:db8::1]:8080/device%20name.xml?x=1", 1},
                {"LOCATION:", "LOCATION: http://[not-ip]/", 0},
                {"LOCATION:", "LOCATION: http://user@host/", 0},
                {"LOCATION:", "LOCATION: http:///missing", 0},
                {"LOCATION:", "LOCATION: http://host:65536/", 0},
                {"LOCATION:", "LOCATION: http://host:0/", 0},
                {"LOCATION:", "LOCATION: http://host/%zz", 0},
                {"LOCATION:", "LOCATION: http://host/#fragment", 0},
                {"LOCATION:", "LOCATION: file:///device.xml", 0},
                {"SERVER:", "SERVER: Test/1 UPnP/2.0 Product/1", 0},
                {"SERVER:", "SERVER: Test/1 UPnP/2.0 Product/1\r\nBOOTID.UPNP.ORG: 1", 1},
                {"SERVER:", "SERVER: Test/1 UPnP/1.1 Product/1\r\nBOOTID.UPNP.ORG: 0", 1},
                {"SERVER:", "SERVER: Test/1 UPnP/2.0 Product/1\r\nBOOTID.UPNP.ORG: 2147483648", 0},
                {"ST:", "ST: ssdp:all", 0},
                {"ST:", "ST: upnp:rootdevice\r\nST: upnp:rootdevice", 0},
                {"ST:", "ST: upnp:rootdevice\r\nX-Extension: yes", 1},
                {"ST:", "ST: upnp:rootdevice\r\nCONFIGID.UPNP.ORG: 16777216", 0},
                {"ST:", "ST: upnp:rootdevice\r\nSEARCHPORT.UPNP.ORG: 65535", 1},
                {"USN:", "USN: uuid:12345678-1234-1234-1234-123456789abz::upnp:rootdevice", 0},
                {"USN:", "USN: uuid:12345678-1234-1234-1234-123456789abc", 0}
            };
            unsigned char altered[1400];
            struct UdpProbeTarget target = {0};
            static const char request[] = "M-SEARCH * HTTP/1.1\r\nHOST: 192.0.2.1:1900\r\n"
                "MAN: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\n\r\n";
            target.destination.version = 4;
            target.destination.ipv4 = 0xc0000201;
            if (udp_probe_prepare(1900, cookie, NULL, &result) ||
                !udp_probe_prepare(1900, cookie, &target, &result) ||
                result.length != sizeof(request) - 1 || memcmp(result.payload, request, result.length)) return 1;
            for (i = 0; i < sizeof(reply) - 1; i++)
                if (udp_probe_classify(1900, reply, i, cookie) != PROTO_NONE) return 1;
            if (udp_probe_classify(1900, reply, sizeof(reply), cookie) != PROTO_NONE) return 1;
            for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                const char *begin = strstr((const char *)reply, cases[i].field);
                const char *end = strstr(begin, "\r\n");
                unsigned prefix = (unsigned)(begin - (const char *)reply);
                unsigned replacement = (unsigned)strlen(cases[i].line);
                unsigned suffix = (unsigned)strlen(end);
                memcpy(altered, reply, prefix);
                memcpy(altered + prefix, cases[i].line, replacement);
                memcpy(altered + prefix + replacement, end, suffix);
                if ((udp_probe_classify(1900, altered, prefix + replacement + suffix, cookie) == PROTO_SSDP)
                    != cases[i].valid) return 1;
            }
            memcpy(altered, reply, sizeof(reply) - 1);
            altered[15] = '\n';
            if (udp_probe_classify(1900, altered, sizeof(reply) - 1, cookie) != PROTO_NONE) return 1;
        }
    }
    {
        static const unsigned char reply[] = "\x05\x4d\x00"
            "ServerName;db;InstanceName;MSSQLSERVER;IsClustered;No;Version;16.0;tcp;1433;;";
        if (udp_probe_classify(1434, reply, sizeof(reply) - 1, cookie) != PROTO_SQL_BROWSER) return 1;
        {
            static const struct {const char *text; int valid;} cases[] = {
                {"ServerName;;InstanceName;;IsClustered;No;Version;.;", 0},
                {"ServerName;;InstanceName;;IsClustered;No;Version;.;;", 1},
                {"servername;db;instancename;a;isclustered;yes;version;1;TCP;65535;np;pipe;;", 1},
                {"ServerName;db;InstanceName;a;IsClustered;No;Version;1;bv;a;b;c;d;e;via;host,1:2,3:4;rpc;host;spx;s;adsp;a;np;p;tcp;1;;", 1},
                {"ServerName;db;InstanceName;a;IsClustered;No;Version;1;bv;a;b;c;d;;", 0},
                {"ServerName;db;InstanceName;a;IsClustered;No;Version;1;tcp;0;;", 0},
                {"ServerName;db;InstanceName;a;IsClustered;No;Version;1;tcp;65536;;", 0},
                {"ServerName;db;InstanceName;a;IsClustered;No;Version;1;tcp;-1;;", 0},
                {"ServerName;db;InstanceName;a;IsClustered;No;Version;1;tcp;2;TCP;2;;", 0},
                {"ServerName;db;InstanceName;a;IsClustered;No;Version;1;via;abcdefghijklmnop,1:2;;", 0},
                {"ServerName;db;InstanceName;a;IsClustered;No;Version;1;via;host,1;;", 0},
                {"ServerName;db;InstanceName;a;IsClustered;No;Version;1;via;host,1:2,;;", 0},
                {"ServerName;db;InstanceName;a;IsClustered;No;Version;1;via;host,1:x;;", 0},
                {"ServerName;db;InstanceName;a;IsClustered;No;Version;x;;", 0},
                {"ServerName;db;InstanceName;a;IsClustered;No;Version;;;", 0},
                {"ServerName;db;InstanceName;a;IsClustered;Maybe;Version;1;;", 0},
                {"ServerName;db;InstanceName;a;IsClustered;No;Version;12345678901234567;;", 0},
                {"ServerName;db;InstanceName;a;IsClustered;No;Version;1;unknown;a;;", 0},
                {"InstanceName;db;ServerName;a;IsClustered;No;Version;1;;", 0}
            };
            unsigned char altered[1100];
            unsigned n;
            for (i = 0; i < sizeof(reply) - 1; i++)
                if (udp_probe_classify(1434, reply, i, cookie) != PROTO_NONE) return 1;
            if (udp_probe_classify(1434, reply, sizeof(reply), cookie) != PROTO_NONE) return 1;
            if (!udp_probe_prepare(1434, cookie, NULL, &result) || result.length != 1 ||
                result.payload[0] != 3) return 1;
            memcpy(altered, reply, 80);
            altered[1] = 0;
            altered[2] = 77;
            if (udp_probe_classify(1434, altered, 80, cookie) != PROTO_NONE) return 1;
            memcpy(altered, reply, 80);
            memcpy(altered + 80, reply + 3, 77);
            altered[1] = 154;
            if (udp_probe_classify(1434, altered, 157, cookie) != PROTO_SQL_BROWSER) return 1;
            for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
                n = (unsigned)strlen(cases[i].text);
                altered[0] = 5;
                altered[1] = (unsigned char)n;
                altered[2] = (unsigned char)(n >> 8);
                memcpy(altered + 3, cases[i].text, n);
                if ((udp_probe_classify(1434, altered, n + 3, cookie) == PROTO_SQL_BROWSER) != cases[i].valid)
                    return 1;
            }
            memcpy(altered, reply, 80);
            altered[14] = 0;
            if (udp_probe_classify(1434, altered, 80, cookie) != PROTO_NONE) return 1;
            altered[14] = 0x81;
            if (udp_probe_classify(1434, altered, 80, cookie) != PROTO_SQL_BROWSER) return 1;
            memcpy(altered + 3, "ServerName;", 11);
            memset(altered + 14, 'x', 256);
            memcpy(altered + 270, ";InstanceName;a;IsClustered;No;Version;1;;", 42);
            altered[0] = 5;
            altered[1] = 53;
            altered[2] = 1;
            if (udp_probe_classify(1434, altered, 312, cookie) != PROTO_NONE) return 1;
            memmove(altered + 269, altered + 270, 42);
            altered[1] = 52;
            if (udp_probe_classify(1434, altered, 311, cookie) != PROTO_SQL_BROWSER) return 1;
        }
    }
    {
        static const unsigned char reply[] =
            "\xcd\xef\x84\x00\x00\x01\x00\x01\x00\x00\x00\x00"
            "\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"
            "\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x0a\x00\x0d"
            "\x05_http\x04_tcp\xc0\x23";
        if (udp_probe_classify(5353, reply, sizeof(reply) - 1, cookie) != PROTO_MDNS)
            return 1;
        {
            static const unsigned char request[] =
                "\xcd\xef\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                "\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01";
            static const unsigned offsets[] = {0, 2, 3, 5, 7, 13, 43, 45, 49, 51, 57, 59};
            unsigned char altered[100];
            struct UdpProbeTarget target = {0};
            if (!udp_probe_prepare(5353, cookie, NULL, &result) ||
                result.length != sizeof(request) - 1 ||
                memcmp(result.payload, request, sizeof(request) - 1)) return 1;
            target.source_port = 5353;
            if (udp_probe_prepare(5353, cookie, &target, &result)) return 1;
            for (i = 0; i < sizeof(reply) - 1; i++)
                if (udp_probe_classify(5353, reply, i, cookie) != PROTO_NONE) return 1;
            if (udp_probe_classify(5353, reply, sizeof(reply), cookie) != PROTO_NONE ||
                udp_probe_classify(5353, reply, sizeof(reply) - 1, cookie ^ 1) != PROTO_NONE) return 1;
            for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
                memcpy(altered, reply, sizeof(reply) - 1);
                altered[offsets[i]] ^= 1;
                if (udp_probe_classify(5353, altered, sizeof(reply) - 1, cookie) != PROTO_NONE) return 1;
            }
            memcpy(altered, reply, 71);
            altered[2] |= 2;
            if (udp_probe_classify(5353, altered, 71, cookie) != PROTO_NONE) return 1;
            memcpy(altered, reply, 71);
            altered[50] |= 128;
            if (udp_probe_classify(5353, altered, 71, cookie) != PROTO_NONE) return 1;
            memcpy(altered, reply, 71);
            altered[47] = 46;
            if (udp_probe_classify(5353, altered, 71, cookie) != PROTO_NONE) return 1;
            memcpy(altered, reply, 71);
            altered[70] = 58;
            if (udp_probe_classify(5353, altered, 71, cookie) != PROTO_NONE) return 1;
            memcpy(altered, reply, 71);
            altered[14] = 'S';
            altered[60] = 'H';
            if (udp_probe_classify(5353, altered, 71, cookie) != PROTO_MDNS) return 1;
            memcpy(altered, reply, 71);
            altered[11] = 1;
            memcpy(altered + 71, "\xc0\x23\x00\x01\x00\x01\x00\x00\x00\x0a\x00\x04\xc0\x00\x02\x01", 16);
            if (udp_probe_classify(5353, altered, 87, cookie) != PROTO_MDNS) return 1;
            altered[82] = 5;
            if (udp_probe_classify(5353, altered, 87, cookie) != PROTO_NONE) return 1;
        }
    }
    {
        static const unsigned char reply[] =
            "\x30\x60\x02\x01\x03\x30\x10\x02\x04\x09\xab\xcd\xef\x02\x02\x05\xdc"
            "\x04\x01\x00\x02\x01\x03\x04\x19\x30\x17\x04\x09\x80\x00\x00\x01\x04test"
            "\x02\x01\x00\x02\x01\x00\x04\x00\x04\x00\x04\x00\x30\x2e\x04\x09"
            "\x80\x00\x00\x01\x04test\x04\x00\xa8\x1f\x02\x04\x09\xab\xcd\xef"
            "\x02\x01\x00\x02\x01\x00\x30\x11\x30\x0f\x06\x0a\x2b\x06\x01\x06"
            "\x03\x0f\x01\x01\x04\x00\x41\x01\x01";
        if (udp_probe_classify(161, reply, sizeof(reply) - 1, cookie) != PROTO_SNMP)
            return 1;
        {
            static const unsigned ports[] = {161, 162, 391, 705, 1993};
            static const unsigned char request[] =
                "\x30\x3d\x02\x01\x03\x30\x10\x02\x04\x09\xab\xcd\xef"
                "\x02\x02\x05\xdc\x04\x01\x04\x02\x01\x03"
                "\x04\x10\x30\x0e\x04\x00\x02\x01\x00\x02\x01\x00\x04\x00\x04\x00\x04\x00"
                "\x30\x14\x04\x00\x04\x00\xa0\x0e\x02\x04\x09\xab\xcd\xef"
                "\x02\x01\x00\x02\x01\x00\x30\x00";
            unsigned p;
            unsigned char altered[104];
            for (p = 0; p < sizeof(ports) / sizeof(ports[0]); p++) {
                if (!udp_probe_prepare(ports[p], cookie, NULL, &result) ||
                    result.length != sizeof(request) - 1 ||
                    memcmp(result.payload, request, sizeof(request) - 1)) return 1;
                if (udp_probe_classify(ports[p], reply, sizeof(reply) - 1, cookie) != PROTO_SNMP ||
                    udp_probe_classify(ports[p], reply, sizeof(reply) - 1, cookie ^ 1) != PROTO_NONE ||
                    udp_probe_classify(ports[p], reply, sizeof(reply), cookie) != PROTO_NONE) return 1;
                for (i = 0; i < sizeof(reply) - 1; i++)
                    if (udp_probe_classify(ports[p], reply, i, cookie) != PROTO_NONE) return 1;
            }
            {
                static const unsigned offsets[] = {0, 4, 19, 22, 28, 54, 65, 72, 75, 78, 94, 95, 96};
                for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
                    memcpy(altered, reply, sizeof(reply) - 1);
                    altered[offsets[i]] ^= 1;
                    if (udp_probe_classify(161, altered, sizeof(reply) - 1, cookie) != PROTO_NONE) return 1;
                }
            }
            memcpy(altered, reply, 98);
            altered[68] = 1;
            altered[69] = 0;
            memmove(altered + 70, altered + 73, 25);
            altered[1] -= 3;
            altered[51] -= 3;
            altered[66] -= 3;
            if (udp_probe_classify(161, altered, 95, cookie) != PROTO_SNMP) return 1;
            memcpy(altered, reply, 98);
            altered[53] = 0;
            memmove(altered + 54, altered + 63, 35);
            altered[1] -= 9;
            altered[51] -= 9;
            if (udp_probe_classify(161, altered, 89, cookie) != PROTO_SNMP) return 1;
            memcpy(altered, reply, 98);
            altered[1] = 0x81;
            altered[2] = 0x60;
            memcpy(altered + 3, reply + 2, 96);
            if (udp_probe_classify(161, altered, 99, cookie) != PROTO_SNMP) return 1;
            altered[1] = 0x80;
            if (udp_probe_classify(161, altered, 99, cookie) != PROTO_NONE) return 1;
            memcpy(altered, reply, 98);
            altered[97] = 128;
            if (udp_probe_classify(161, altered, 98, cookie) != PROTO_NONE) return 1;
            altered[96] = 5;
            memcpy(altered + 97, "\x00\xff\xff\xff\xff", 5);
            altered[1] += 4;
            altered[51] += 4;
            altered[66] += 4;
            altered[80] += 4;
            altered[82] += 4;
            if (udp_probe_classify(161, altered, 102, cookie) != PROTO_SNMP) return 1;
            altered[97] = 1;
            if (udp_probe_classify(161, altered, 102, cookie) != PROTO_NONE) return 1;
            memcpy(altered, reply, 98);
            memset(altered + 29, 0, 9);
            if (udp_probe_classify(161, altered, 98, cookie) != PROTO_NONE) return 1;
            memset(altered + 29, 255, 9);
            if (udp_probe_classify(161, altered, 98, cookie) != PROTO_NONE) return 1;
            if (!udp_probe_prepare(161, 0, NULL, &result) || result.length != 57 ||
                memcmp(result.payload + 7, "\x02\x01\x00", 3)) return 1;
            if (!udp_probe_prepare(161, 127, NULL, &result) || result.length != 57 ||
                memcmp(result.payload + 7, "\x02\x01\x7f", 3)) return 1;
            if (!udp_probe_prepare(161, 128, NULL, &result) || result.length != 59 ||
                memcmp(result.payload + 7, "\x02\x02\x00\x80", 4)) return 1;
            if (!udp_probe_prepare(161, 0x7fffffff, NULL, &result) || result.length != 63 ||
                memcmp(result.payload + 7, "\x02\x04\x7f\xff\xff\xff", 6)) return 1;
        }
    }
    {
        unsigned char reply[70] = {0};
        reply[0] = 0x63;
        reply[2] = 41;
        reply[24] = 1;
        reply[26] = 12;
        reply[28] = 35;
        reply[30] = 1;
        reply[33] = 2;
        reply[62] = 1;
        reply[63] = 'x';
        if (udp_probe_classify(44818, reply, 65, cookie) != PROTO_ENIP)
            return 1;
        for (i = 0; i < 65; i++)
            if (udp_probe_classify(44818, reply, i, cookie) != PROTO_NONE) return 1;
        if (udp_probe_classify(44818, reply, 66, cookie) != PROTO_NONE) return 1;
        reply[12] = 1;
        if (udp_probe_classify(44818, reply, 65, cookie) != PROTO_NONE) return 1;
        reply[12] = 0;
        reply[8] = 1;
        if (udp_probe_classify(44818, reply, 65, cookie) != PROTO_NONE) return 1;
        reply[8] = 0;
        reply[62] = 2;
        if (udp_probe_classify(44818, reply, 65, cookie) != PROTO_NONE) return 1;
        reply[62] = 0;
        reply[28] = 34;
        reply[2] = 40;
        if (udp_probe_classify(44818, reply, 64, cookie) != PROTO_ENIP) return 1;
        reply[62] = 1;
        reply[28] = 35;
        reply[2] = 41;
        reply[32] = 2;
        reply[33] = 0;
        if (udp_probe_classify(44818, reply, 65, cookie) != PROTO_NONE) return 1;
        reply[32] = 0;
        reply[33] = 2;
        reply[2] = 46;
        reply[24] = 2;
        memcpy(reply + 65, "\x22\x00\x01\x00\x01", 5);
        if (udp_probe_classify(44818, reply, 70, cookie) != PROTO_ENIP) return 1;
        reply[26] = 22;
        if (udp_probe_classify(44818, reply, 70, cookie) != PROTO_NONE) return 1;
        reply[26] = 12;
        reply[67] = 2;
        if (udp_probe_classify(44818, reply, 70, cookie) != PROTO_NONE) return 1;
        if (!udp_probe_prepare(44818, cookie, NULL, &result) || result.length != 24 ||
            result.payload[0] != 0x63) return 1;
        for (i = 1; i < 24; i++)
            if (result.payload[i] != 0) return 1;
    }
    {
        static const unsigned char reply[] = "1:42:node:host:65:IP Messenger 5.0";
        if (udp_probe_classify(2425, reply, sizeof(reply), cookie) != PROTO_IPMSG)
            return 1;
        for (i = 0; i < sizeof(reply); i++)
            if (udp_probe_classify(2425, reply, i, cookie) != PROTO_NONE) return 1;
        {
            static const char *bad[] = {
                "2:42:node:host:65:version", "1::node:host:65:version",
                "1:18446744073709551616:node:host:65:version",
                "1:42:node:host:4294967361:version", "1:42:node:host:64:version",
                "1:42:node:host:65:", "1:42:node:host:x:version", "1:42:node:host"
            };
            for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
                if (udp_probe_classify(2425, (const unsigned char *)bad[i],
                                       (unsigned)strlen(bad[i]) + 1, cookie) != PROTO_NONE) return 1;
        }
        {
            static const unsigned char extended[] = "1:18446744073709551615:u:h:321:Version: 2";
            static const unsigned char embedded[] = "1:42:u:h:65:v\0more";
            if (udp_probe_classify(2425, extended, sizeof(extended), cookie) != PROTO_IPMSG ||
                udp_probe_classify(2425, embedded, sizeof(embedded), cookie) != PROTO_NONE) return 1;
        }
        if (!udp_probe_prepare(2425, 1, NULL, &result) ||
            result.length != sizeof("1:1:scanner:scanner:64:") ||
            memcmp(result.payload, "1:1:scanner:scanner:64:", result.length)) return 1;
    }
    {
        unsigned char reply[24] = {
            0x40, 2, 0, 9, 0xab, 0xcd, 0xef, 0, 3, 0, 1, 0, 7
        };
        if (udp_probe_classify(2123, reply, 13, cookie) != PROTO_GTPC)
            return 1;
        for (i = 0; i < 13; i++)
            if (udp_probe_classify(2123, reply, i, cookie) != PROTO_NONE) return 1;
        if (udp_probe_classify(2123, reply, 14, cookie) != PROTO_NONE ||
            udp_probe_classify(2123, reply, 13, cookie ^ 1) != PROTO_NONE) return 1;
        reply[0] = 0x48;
        if (udp_probe_classify(2123, reply, 13, cookie) != PROTO_NONE) return 1;
        reply[0] = 0x50;
        if (udp_probe_classify(2123, reply, 13, cookie) != PROTO_NONE) return 1;
        reply[0] = 0x40;
        reply[1] = 3;
        if (udp_probe_classify(2123, reply, 13, cookie) != PROTO_NONE) return 1;
        reply[1] = 2;
        reply[8] = 152;
        if (udp_probe_classify(2123, reply, 13, cookie) != PROTO_NONE) return 1;
        reply[8] = 3;
        reply[11] = 1;
        if (udp_probe_classify(2123, reply, 13, cookie) != PROTO_NONE) return 1;
        reply[11] = 0;
        reply[3] = 20;
        memcpy(reply + 13, "\x98\x00\x01\x00\xff\xff\x00\x02\x07\x00\x01", 11);
        if (udp_probe_classify(2123, reply, 24, cookie) != PROTO_GTPC) return 1;
        reply[13] = 3;
        if (udp_probe_classify(2123, reply, 24, cookie) != PROTO_NONE) return 1;
        reply[13] = 152;
        reply[15] = 0;
        if (udp_probe_classify(2123, reply, 24, cookie) != PROTO_NONE) return 1;
        reply[15] = 1;
        reply[20] = 3;
        if (udp_probe_classify(2123, reply, 24, cookie) != PROTO_NONE) return 1;
        reply[20] = 1;
        if (udp_probe_classify(2123, reply, 24, cookie) != PROTO_NONE) return 1;
        if (!udp_probe_prepare(2123, cookie, NULL, &result) || result.length != 13 ||
            memcmp(result.payload, "\x40\x01\x00\x09\xab\xcd\xef\x00\x03\x00\x01\x00\x00", 13))
            return 1;
    }
    {
        unsigned char reply[94] = {0};
        memcpy(reply + 8, "\x89\xab\xcd\xef", 4);
        reply[20] = 13;
        reply[21] = 4;
        memcpy(reply + 28, "AFS test", 8);
        if (udp_probe_classify(7001, reply, 93, cookie) != PROTO_AFS)
            return 1;
        for (i = 0; i < 93; i++)
            if (udp_probe_classify(7001, reply, i, cookie) != PROTO_NONE) return 1;
        if (udp_probe_classify(7001, reply, 94, cookie) != PROTO_NONE ||
            udp_probe_classify(7001, reply, 93, cookie ^ 1) != PROTO_NONE) return 1;
        for (i = 0; i < 28; i++) {
            reply[i] ^= 1;
            if (udp_probe_classify(7001, reply, 93, cookie) != PROTO_NONE) return 1;
            reply[i] ^= 1;
        }
        memset(reply + 28, 'v', 65);
        if (udp_probe_classify(7001, reply, 93, cookie) != PROTO_AFS) return 1;
        reply[29] = 0;
        if (udp_probe_classify(7001, reply, 93, cookie) != PROTO_NONE) return 1;
        memset(reply + 28, 0, 65);
        if (udp_probe_classify(7001, reply, 93, cookie) != PROTO_NONE) return 1;
        if (!udp_probe_prepare(7001, cookie, NULL, &result) || result.length != 29 ||
            result.payload[20] != 13 || result.payload[21] != 5 || result.payload[28] != 0 ||
            memcmp(result.payload + 8, "\x89\xab\xcd\xef", 4)) return 1;
    }
    {
        unsigned char reply[16] = {0x54, 0x45, 0, 1, 0x89, 0xab, 0xcd, 0xef};
        if (udp_probe_classify(5683, reply, 8, cookie) != PROTO_COAP)
            return 1;
        for (i = 0; i < 8; i++)
            if (udp_probe_classify(5683, reply, i, cookie) != PROTO_NONE) return 1;
        if (udp_probe_classify(5683, reply, 8, cookie ^ 1) != PROTO_NONE) return 1;
        reply[0] = 0x44;
        reply[1] = 0x84;
        if (udp_probe_classify(5683, reply, 8, cookie) != PROTO_COAP) return 1;
        reply[0] = 0x64;
        if (udp_probe_classify(5683, reply, 8, cookie) != PROTO_NONE) return 1;
        reply[2] = 0xcd;
        reply[3] = 0xef;
        if (udp_probe_classify(5683, reply, 8, cookie) != PROTO_COAP) return 1;
        reply[0] = 0x55;
        if (udp_probe_classify(5683, reply, 8, cookie) != PROTO_NONE) return 1;
        reply[0] = 0x54;
        reply[1] = 1;
        if (udp_probe_classify(5683, reply, 8, cookie) != PROTO_NONE) return 1;
        reply[1] = 0x45;
        reply[8] = 255;
        if (udp_probe_classify(5683, reply, 9, cookie) != PROTO_NONE) return 1;
        reply[9] = 'x';
        if (udp_probe_classify(5683, reply, 10, cookie) != PROTO_COAP) return 1;
        reply[8] = 0xc1;
        reply[9] = 40;
        if (udp_probe_classify(5683, reply, 10, cookie) != PROTO_COAP) return 1;
        reply[10] = 0;
        if (udp_probe_classify(5683, reply, 11, cookie) != PROTO_NONE) return 1;
        reply[8] = 0xf0;
        if (udp_probe_classify(5683, reply, 10, cookie) != PROTO_NONE) return 1;
        reply[8] = 0x10;
        if (udp_probe_classify(5683, reply, 9, cookie) != PROTO_NONE) return 1;
        reply[8] = 0xd0;
        reply[9] = 3;
        if (udp_probe_classify(5683, reply, 9, cookie) != PROTO_NONE ||
            udp_probe_classify(5683, reply, 10, cookie) != PROTO_COAP) return 1;
        reply[8] = 0x0e;
        reply[9] = reply[10] = 255;
        if (udp_probe_classify(5683, reply, 11, cookie) != PROTO_NONE) return 1;
        if (!udp_probe_prepare(5683, cookie, NULL, &result) || result.length != 25 ||
            memcmp(result.payload, "\x44\x01\xcd\xef\x89\xab\xcd\xef\xbb.well-known\x04" "core", 25))
            return 1;
    }
    {
        unsigned char reply[29] = {
            6, 0, 255, 6, 0, 0, 0x11, 0xbe, 0x40, 0xf2, 0, 16,
            0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4, 0x80, 0, 0, 0, 0, 0, 0, 0
        };
        if (udp_probe_classify(623, reply, 28, cookie) != PROTO_IPMI)
            return 1;
        for (i = 0; i < 28; i++)
            if (udp_probe_classify(623, reply, i, cookie) != PROTO_NONE) return 1;
        if (udp_probe_classify(623, reply, 29, cookie) != PROTO_NONE ||
            udp_probe_classify(623, reply, 28, cookie ^ 1) != PROTO_NONE) return 1;
        reply[9] = 255;
        if (udp_probe_classify(623, reply, 28, cookie) != PROTO_NONE) return 1;
        reply[9] = 0xf2;
        reply[20] = 1;
        if (udp_probe_classify(623, reply, 28, cookie) != PROTO_NONE) return 1;
        reply[20] = 0x81;
        if (udp_probe_classify(623, reply, 28, cookie) != PROTO_IPMI) return 1;
        reply[11] = 15;
        if (udp_probe_classify(623, reply, 28, cookie) != PROTO_NONE) return 1;
        reply[11] = 16;
        for (i = 0; i < 9; i++) {
            reply[i] ^= 1;
            if (udp_probe_classify(623, reply, 28, cookie) != PROTO_NONE) return 1;
            reply[i] ^= 1;
        }
        if (!udp_probe_prepare(623, cookie, NULL, &result) || result.length != 12 ||
            memcmp(result.payload, "\x06\x00\xff\x06\x00\x00\x11\xbe\x80\xf2\x00\x00", 12))
            return 1;
        if (!udp_probe_prepare(623, 255, NULL, &result) || result.payload[9] != 0) return 1;
    }
    {
        unsigned char reply[25] = {
            2, 1, 0, 0, 0, 2, 0, 0, 192, 0, 2, 1,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16
        };
        if (udp_probe_classify(520, reply, 24, cookie) != PROTO_RIP)
            return 1;
        for (i = 0; i < 24; i++)
            if (udp_probe_classify(520, reply, i, cookie) != PROTO_NONE) return 1;
        if (udp_probe_classify(520, reply, 25, cookie) != PROTO_NONE) return 1;
        reply[1] = 2;
        if (udp_probe_classify(520, reply, 24, cookie) != PROTO_NONE) return 1;
        reply[1] = 1;
        reply[11] = 2;
        if (udp_probe_classify(520, reply, 24, cookie) != PROTO_NONE) return 1;
        reply[11] = 1;
        reply[23] = 0;
        if (udp_probe_classify(520, reply, 24, cookie) != PROTO_NONE) return 1;
        reply[23] = 17;
        if (udp_probe_classify(520, reply, 24, cookie) != PROTO_NONE) return 1;
        reply[23] = 1;
        if (udp_probe_classify(520, reply, 24, cookie) != PROTO_RIP) return 1;
        reply[12] = 1;
        if (udp_probe_classify(520, reply, 24, cookie) != PROTO_NONE) return 1;
        if (!udp_probe_prepare(520, cookie, NULL, &result) || result.length != 24 ||
            memcmp(result.payload, "\x01\x01\x00\x00\x00\x02\x00\x00\xc0\x00\x02\x01"
                   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10", 24)) return 1;
    }
    {
        unsigned ports[] = {443, 2491};
        for (i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
            if (!udp_probe_prepare(ports[i], cookie, NULL, &result) ||
                result.length != UDP_PROBE_MAX_PAYLOAD ||
                udp_probe_classify(ports[i], version_negotiation,
                                   sizeof(version_negotiation), cookie) != PROTO_QUIC ||
                udp_probe_classify(ports[i], version_negotiation,
                                   sizeof(version_negotiation), cookie ^ 1) != PROTO_NONE ||
                udp_probe_classify(ports[i], version_negotiation, 14, cookie) != PROTO_NONE)
                return 1;
        }
    }
    {
        unsigned char reply[19] = {
            0x32, 2, 0, 6, 0, 0, 0, 0, 0xcd, 0xef, 0, 0, 14, 7
        };
        if (udp_probe_classify(2152, reply, 14, cookie) != PROTO_GTPU)
            return 1;
        for (i = 0; i < 14; i++)
            if (udp_probe_classify(2152, reply, i, cookie) != PROTO_NONE) return 1;
        if (udp_probe_classify(2152, reply, 14, cookie ^ 1) != PROTO_NONE ||
            udp_probe_classify(2152, reply, 15, cookie) != PROTO_NONE) return 1;
        reply[0] = 0x30;
        if (udp_probe_classify(2152, reply, 14, cookie) != PROTO_NONE) return 1;
        reply[0] = 0x36;
        if (udp_probe_classify(2152, reply, 14, cookie) != PROTO_NONE) return 1;
        reply[0] = 0x22;
        if (udp_probe_classify(2152, reply, 14, cookie) != PROTO_NONE) return 1;
        reply[0] = 0x3b;
        reply[10] = reply[11] = 0xff;
        if (udp_probe_classify(2152, reply, 14, cookie) != PROTO_GTPU) return 1;
        reply[1] = 26;
        if (udp_probe_classify(2152, reply, 14, cookie) != PROTO_NONE) return 1;
        reply[1] = 2;
        reply[7] = 1;
        if (udp_probe_classify(2152, reply, 14, cookie) != PROTO_NONE) return 1;
        reply[7] = 0;
        reply[12] = 15;
        if (udp_probe_classify(2152, reply, 14, cookie) != PROTO_NONE) return 1;
        reply[12] = 14;
        reply[3] = 11;
        reply[14] = 255;
        reply[16] = 2;
        if (udp_probe_classify(2152, reply, 19, cookie) != PROTO_GTPU) return 1;
        reply[16] = 3;
        if (udp_probe_classify(2152, reply, 19, cookie) != PROTO_NONE) return 1;
        reply[16] = 1;
        if (udp_probe_classify(2152, reply, 19, cookie) != PROTO_NONE) return 1;
        reply[14] = 14;
        if (udp_probe_classify(2152, reply, 19, cookie) != PROTO_NONE) return 1;
        if (!udp_probe_prepare(2152, cookie, NULL, &result) || result.length != 12 ||
            memcmp(result.payload, "\x32\x01\x00\x04\x00\x00\x00\x00\xcd\xef\x00\x00", 12))
            return 1;
    }
    {
        unsigned char reply[425] = {
            0x89, 0xab, 0xcd, 0xef, 0, 0, 0, 1,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
        };
        if (udp_probe_classify(111, reply, 24, cookie) != PROTO_RPC)
            return 1;
        for (i = 0; i < 24; i++)
            if (udp_probe_classify(111, reply, i, cookie) != PROTO_NONE) return 1;
        if (udp_probe_classify(111, reply, 25, cookie) != PROTO_NONE ||
            udp_probe_classify(111, reply, 24, cookie ^ 1) != PROTO_NONE) return 1;
        for (i = 1; i <= 5; i++) {
            reply[23] = (unsigned char)i;
            if (i == 2) {
                reply[27] = 1;
                reply[31] = 2;
                if (udp_probe_classify(111, reply, 32, cookie) != PROTO_RPC) return 1;
                reply[27] = 3;
                if (udp_probe_classify(111, reply, 32, cookie) != PROTO_NONE) return 1;
                reply[27] = reply[31] = 0;
            } else if (udp_probe_classify(111, reply, 24, cookie) != PROTO_RPC) return 1;
        }
        reply[23] = 6;
        if (udp_probe_classify(111, reply, 24, cookie) != PROTO_NONE) return 1;
        reply[23] = 0;
        reply[19] = 1;
        reply[20] = 0xa5;
        if (udp_probe_classify(111, reply, 28, cookie) != PROTO_RPC) return 1;
        reply[21] = 1;
        if (udp_probe_classify(111, reply, 28, cookie) != PROTO_NONE) return 1;
        memset(reply + 20, 0, sizeof(reply) - 20);
        reply[18] = 1;
        reply[19] = 144;
        if (udp_probe_classify(111, reply, 424, cookie) != PROTO_RPC) return 1;
        reply[19] = 145;
        if (udp_probe_classify(111, reply, sizeof(reply), cookie) != PROTO_NONE) return 1;
        memset(reply + 8, 0, sizeof(reply) - 8);
        reply[11] = 1;
        reply[19] = 2;
        reply[23] = 3;
        if (udp_probe_classify(111, reply, 24, cookie) != PROTO_RPC) return 1;
        reply[15] = 1;
        if (udp_probe_classify(111, reply, 20, cookie) != PROTO_RPC) return 1;
        reply[19] = 15;
        if (udp_probe_classify(111, reply, 20, cookie) != PROTO_NONE) return 1;
        reply[11] = 2;
        if (udp_probe_classify(111, reply, 24, cookie) != PROTO_NONE) return 1;
        if (!udp_probe_prepare(111, cookie, NULL, &result) || result.length != 40 ||
            memcmp(result.payload, "\x89\xab\xcd\xef\x00\x00\x00\x00"
                   "\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02", 20)) return 1;
        for (i = 20; i < 40; i++)
            if (result.payload[i] != 0) return 1;
    }
    {
        unsigned char reply[13] = {0, 128, 0, 0, 0, 0, 0, 1, 192, 0, 2, 1};
        if (udp_probe_classify(5351, reply, 12, cookie) != PROTO_NATPMP)
            return 1;
        for (i = 0; i < 12; i++)
            if (udp_probe_classify(5351, reply, i, cookie) != PROTO_NONE) return 1;
        if (udp_probe_classify(5351, reply, 13, cookie) != PROTO_NONE) return 1;
        for (i = 1; i <= 5; i++) {
            reply[3] = (unsigned char)i;
            if (udp_probe_classify(5351, reply, 12, cookie) != PROTO_NATPMP) return 1;
        }
        reply[3] = 6;
        if (udp_probe_classify(5351, reply, 12, cookie) != PROTO_NONE) return 1;
        reply[3] = 0;
        reply[0] = 2;
        if (udp_probe_classify(5351, reply, 12, cookie) != PROTO_NONE) return 1;
        reply[0] = 0;
        reply[1] = 129;
        if (udp_probe_classify(5351, reply, 12, cookie) != PROTO_NONE) return 1;
        if (!udp_probe_prepare(5351, cookie, NULL, &result) || result.length != 2 ||
            result.payload[0] != 0 || result.payload[1] != 0) return 1;
    }
    {
        unsigned char reply[49] = {0x24, 2};
        memcpy(reply + 24, "\x89\xab\xcd\xef\x76\x54\x32\x10", 8);
        reply[32] = 1;
        reply[40] = 1;
        if (udp_probe_classify(123, reply, 48, cookie) != PROTO_NTP)
            return 1;
        for (i = 0; i < 48; i++)
            if (udp_probe_classify(123, reply, i, cookie) != PROTO_NONE) return 1;
        if (udp_probe_classify(123, reply, 49, cookie) != PROTO_NONE ||
            udp_probe_classify(123, reply, 48, cookie ^ 1) != PROTO_NONE) return 1;
        reply[0] = 0x23;
        if (udp_probe_classify(123, reply, 48, cookie) != PROTO_NONE) return 1;
        reply[0] = 0x14;
        if (udp_probe_classify(123, reply, 48, cookie) != PROTO_NONE) return 1;
        reply[0] = 0x1c;
        if (udp_probe_classify(123, reply, 48, cookie) != PROTO_NTP) return 1;
        reply[1] = 17;
        if (udp_probe_classify(123, reply, 48, cookie) != PROTO_NONE) return 1;
        reply[1] = 16;
        reply[40] = 0;
        if (udp_probe_classify(123, reply, 48, cookie) != PROTO_NONE) return 1;
        reply[1] = 0;
        memcpy(reply + 12, "RATE", 4);
        if (udp_probe_classify(123, reply, 48, cookie) != PROTO_NTP) return 1;
        reply[15] = 0;
        if (udp_probe_classify(123, reply, 48, cookie) != PROTO_NONE) return 1;
        if (!udp_probe_prepare(123, cookie, NULL, &result) || result.length != 48 ||
            result.payload[0] != 0x23 || result.payload[2] != 6 ||
            memcmp(result.payload + 40, "\x89\xab\xcd\xef\x76\x54\x32\x10", 8)) return 1;
    }
    {
        unsigned char reply[] = {0, 1, 0, 5, 0, 9, 0, 0, 0, 1, 'x', 0, 2, 'o', 'k'};
        if (udp_probe_classify(177, reply, sizeof(reply), cookie) != PROTO_XDMCP)
            return 1;
        if (!udp_probe_prepare(177, cookie, NULL, &result) || result.length != 7 ||
            memcmp(result.payload, "\x00\x01\x00\x02\x00\x01\x00", 7)) return 1;
        for (i = 0; i < sizeof(reply); i++) {
            if (udp_probe_classify(177, reply, i, cookie) != PROTO_NONE) return 1;
        }
        reply[12] = 3;
        if (udp_probe_classify(177, reply, sizeof(reply), cookie) != PROTO_NONE) return 1;
        reply[12] = 1;
        if (udp_probe_classify(177, reply, sizeof(reply), cookie) != PROTO_NONE) return 1;
        reply[12] = 2;
        reply[3] = 8;
        if (udp_probe_classify(177, reply, sizeof(reply), cookie) != PROTO_NONE) return 1;
        reply[3] = 6;
        reply[5] = 7;
        memmove(reply + 6, reply + 8, 7);
        if (udp_probe_classify(177, reply, 13, cookie) != PROTO_XDMCP) return 1;
        reply[1] = 2;
        if (udp_probe_classify(177, reply, 13, cookie) != PROTO_NONE) return 1;
    }
    {
        unsigned char reply[25] = {
            2, 10, 0, 0, 24, 0, 0, 0, 0, 0, 0xcd, 0xef, 0, 2,
            'e', 'n', 0, 0, 0, 4, 'h', 't', 't', 'p'
        };
        if (udp_probe_classify(427, reply, 24, cookie) != PROTO_SLP)
            return 1;
        if (!udp_probe_prepare(427, cookie, NULL, &result) || result.length != 29 ||
            memcmp(result.payload,
                "\x02\x09\x00\x00\x1d\x00\x00\x00\x00\x00\xcd\xef\x00\x02"
                "en\x00\x00\xff\xff\x00\x07" "DEFAULT", 29)) return 1;
        for (i = 0; i < 24; i++) {
            if (udp_probe_classify(427, reply, i, cookie) != PROTO_NONE) return 1;
        }
        if (udp_probe_classify(427, reply, 25, cookie) != PROTO_NONE ||
            udp_probe_classify(427, reply, 24, cookie ^ 1) != PROTO_NONE) return 1;
        reply[5] = 0x80;
        if (udp_probe_classify(427, reply, 24, cookie) != PROTO_NONE) return 1;
        reply[5] = 0;
        reply[9] = 20;
        if (udp_probe_classify(427, reply, 24, cookie) != PROTO_NONE) return 1;
        reply[9] = 0;
        memcpy(reply + 20, "\xf0\x9f\x98\x80", 4);
        if (udp_probe_classify(427, reply, 24, cookie) != PROTO_SLP) return 1;
        memcpy(reply + 20, "\xed\xa0\x80x", 4);
        if (udp_probe_classify(427, reply, 24, cookie) != PROTO_NONE) return 1;
        reply[4] = 20;
        reply[19] = 0;
        if (udp_probe_classify(427, reply, 20, cookie) != PROTO_SLP) return 1;
        reply[4] = 18;
        if (udp_probe_classify(427, reply, 18, cookie) != PROTO_NONE) return 1;
        reply[17] = 14;
        if (udp_probe_classify(427, reply, 18, cookie) != PROTO_SLP) return 1;
        reply[17] = 8;
        if (udp_probe_classify(427, reply, 18, cookie) != PROTO_NONE) return 1;
    }

    if (!udp_probe_prepare(64738, cookie, NULL, &result) || result.length != 12)
        return 1;
    if (memcmp(result.payload,
               "\x00\x00\x00\x00\x00\x00\x00\x00\x89\xab\xcd\xef", 12))
        return 1;
    if (udp_probe_classify(64738, mumble_response, 24, cookie) != PROTO_MUMBLE)
        return 1;
    if (udp_probe_classify(64738, mumble_response, 24,
                           cookie | UINT64_C(0x1234567800000000)) != PROTO_MUMBLE)
        return 1;
    for (i = 0; i < 24; i++) {
        if (udp_probe_classify(64738, mumble_response, i, cookie) != PROTO_NONE)
            return 1;
    }
    if (udp_probe_classify(64738, mumble_response, 25, cookie) != PROTO_NONE)
        return 1;
    for (i = 4; i < 12; i++) {
        mumble_response[i] ^= 1;
        if (udp_probe_classify(64738, mumble_response, 24, cookie) != PROTO_NONE)
            return 1;
        mumble_response[i] ^= 1;
    }
    memset(mumble_response, 0, 4);
    if (udp_probe_classify(64738, mumble_response, 24, cookie) != PROTO_NONE)
        return 1;
    mumble_response[1] = 1;
    memset(mumble_response + 12, 0, 12);
    if (udp_probe_classify(64738, mumble_response, 24, cookie) != PROTO_MUMBLE)
        return 1;
    if (udp_probe_classify(64738, NULL, 0, cookie) != PROTO_NONE ||
        udp_probe_classify(64738, NULL, 24, cookie) != PROTO_NONE)
        return 1;

    if (udp_probe_classify(2427, (const unsigned char *)"200 309737970 OK\r\n",
                           18, cookie) != PROTO_MGCP)
        return 1;
    {
        const char *sip = "SIP/2.0 200 OK\r\n"
            "Via: SIP/2.0/UDP 192.0.2.2:40000;branch=z9hG4bK00000001\r\n"
            "Call-ID: scan-00000001@scan.invalid\r\n"
            "CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
        if (udp_probe_classify(6060, (const unsigned char *)sip,
                              (unsigned)strlen(sip), 1) != PROTO_SIP)
            return 1;
        if (udp_probe_classify(5060, (const unsigned char *)sip,
                              (unsigned)strlen(sip), 1) != PROTO_SIP)
            return 1;
        if (udp_probe_classify(5061, (const unsigned char *)sip,
                              (unsigned)strlen(sip), 1) != PROTO_SIP ||
            udp_probe_classify(5061, (const unsigned char *)sip,
                              (unsigned)strlen(sip), 2) != PROTO_NONE ||
            udp_probe_classify(5061, (const unsigned char *)sip, 10, 1) != PROTO_NONE)
            return 1;
        for (i = 0; i < strlen(sip); i++) {
            if (udp_probe_classify(6060, (const unsigned char *)sip, i, 1) != PROTO_NONE)
                return 1;
        }
        if (udp_probe_classify(6060, (const unsigned char *)sip,
                              (unsigned)strlen(sip), 2) != PROTO_NONE)
            return 1;
        {
            char altered[512];
            static const char *fields[] = {"z9hG4bK00000001", "scan-00000001",
                                          "1 OPTIONS", "Content-Length: 0"};
            for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
                char *field;
                memcpy(altered, sip, strlen(sip) + 1);
                field = strstr(altered, fields[i]);
                if (!field) return 1;
                field[strlen(fields[i]) - 1] = '9';
                if (udp_probe_classify(6060, (const unsigned char *)altered,
                                      (unsigned)strlen(altered), 1) != PROTO_NONE)
                    return 1;
            }
        }
        sip = "SIP/2.0 403 Forbidden\r\n"
            "v: SIP/2.0/UDP 192.0.2.2:40000;rport=40000;\r\n"
            " branch=z9hG4bK00000001\r\n"
            "i: scan-00000001@scan.invalid\r\n"
            "cseq: 0001\tOPTIONS\r\nl: 0\r\n\r\n";
        if (udp_probe_classify(6060, (const unsigned char *)sip,
                              (unsigned)strlen(sip), 1) != PROTO_SIP)
            return 1;
        {
            static const char *bad_vias[] = {
                "SIP/2.0/UDP x;branch=z9hG4bK00000001suffix",
                "SIP/2.0/UDP x;branch=wrong, SIP/2.0/UDP y;branch=z9hG4bK00000001",
                "SIP/2.0/UDP x;branch=z9hG4bK00000001;branch=z9hG4bK00000001",
                "SIP/2.0/UDP x;other=\";branch=z9hG4bK00000001\"",
                "SIP/2.0/UDP x;branch=\"z9hG4bK00000001\""
            };
            char packet[512];
            for (i = 0; i < sizeof(bad_vias) / sizeof(bad_vias[0]); i++) {
                int length = snprintf(packet, sizeof(packet),
                    "SIP/2.0 200 OK\r\nVia: %s\r\n"
                    "Call-ID: scan-00000001@scan.invalid\r\n"
                    "CSeq: 1 OPTIONS\r\n\r\n", bad_vias[i]);
                if (length < 0 || (unsigned)length >= sizeof(packet) ||
                    udp_probe_classify(6060, (const unsigned char *)packet,
                                       (unsigned)length, 1) != PROTO_NONE)
                    return 1;
            }
        }
        {
            struct UdpProbeTarget target;
            memset(&target, 0, sizeof(target));
            target.source.version = target.destination.version = 4;
            target.source.ipv4 = 0xc0000202;
            target.destination.ipv4 = 0xc0000201;
            target.source_port = 40000;
            if (!udp_probe_prepare(6060, 1, &target, &result) ||
                strstr((char *)result.payload, "Via: SIP/2.0/UDP 192.0.2.2:40000;") == NULL ||
                strstr((char *)result.payload, "OPTIONS sip:192.0.2.1:6060 SIP/2.0\r\n") == NULL)
                return 1;
            target.source.version = target.destination.version = 6;
            target.source.ipv6.hi = target.destination.ipv6.hi = UINT64_C(0x20010db800000000);
            target.source.ipv6.lo = 2;
            target.destination.ipv6.lo = 1;
            if (!udp_probe_prepare(6060, 1, &target, &result) ||
                strstr((char *)result.payload, "Via: SIP/2.0/UDP [2001:db8::2]:40000;") == NULL)
                return 1;
            if (udp_probe_prepare(6060, 1, NULL, &result)) return 1;
            target.source_port = 0;
            if (udp_probe_prepare(6060, 1, &target, &result)) return 1;
        }
    }
    {
        static const struct {
            const char *response;
            uint64_t cookie;
            int valid;
        } tests[] = {
            {"200 000000001 OK\r\n", 0, 1},
            {"533 1 Response too large\n", 0, 1},
            {"500 1 Unknown endpoint\r\n", 0, 1},
            {"200 1 OK\r\nZ: a@[192.0.2.1]\r\n", 0, 1},
            {"200 2 OK\r\n", 0, 0},
            {"200 1suffix OK\r\n", 0, 0},
            {"200 1000000000 OK\r\n", 0, 0},
            {"200 0 OK\r\n", 0, 0},
            {"600 1 invalid\r\n", 0, 0},
            {"HTTP/1.1 200 OK\r\n", 0, 0},
            {"200 1 bad\rtext\n", 0, 0},
            {"200 1 OK\r", 0, 0},
            {"200 1 OK", 0, 0},
            {"200 1\r\n", 0, 1},
            {"200\t1\tOK\n", 0, 1}
        };
        struct UdpProbeTarget target;
        const char *expected = "AUEP 1 *@[192.0.2.1] MGCP 1.0\r\n";
        memset(&target, 0, sizeof(target));
        target.destination.version = 4;
        target.destination.ipv4 = 0xc0000201;
        if (!udp_probe_prepare(2427, 0, &target, &result) ||
            result.length != strlen(expected) ||
            memcmp(result.payload, expected, result.length) != 0)
            return 1;
        target.destination.version = 6;
        target.destination.ipv6.hi = UINT64_C(0x20010db800000000);
        target.destination.ipv6.lo = 1;
        expected = "AUEP 1 *@[2001:db8::1] MGCP 1.0\r\n";
        if (!udp_probe_prepare(2427, 0, &target, &result) ||
            result.length != strlen(expected) ||
            memcmp(result.payload, expected, result.length) != 0)
            return 1;
        if (udp_probe_prepare(2427, 0, NULL, &result))
            return 1;
        for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
            int valid = udp_probe_classify(2427,
                (const unsigned char *)tests[i].response,
                (unsigned)strlen(tests[i].response), tests[i].cookie) == PROTO_MGCP;
            if (valid != tests[i].valid)
                return 1;
        }
        for (i = 0; i < 10; i++) {
            if (udp_probe_classify(2427, (const unsigned char *)"200 1 OK\r\n",
                                  i, 0) != PROTO_NONE)
                return 1;
        }
    }

    memset(&result, 0xa5, sizeof(result));
    if (udp_probe_prepare(65535, 0, NULL, &result) != 0)
        return 1;
    if (result.port != 0 || result.length != 0)
        return 1;
    if (udp_probe_prepare(65535, 0, NULL, NULL) != 0)
        return 1;
    if (udp_probe_classify(65535, NULL, 0, 0) != PROTO_NONE)
        return 1;
    if (udp_probe_classify(65535, NULL, 1, 0) != PROTO_NONE)
        return 1;

    if (udp_probe_prepare(80, cookie, NULL, &result) == 0)
        return 1;
    if (result.port != 80 || result.length != 1200)
        return 1;
    if (result.payload[0] != 0xc0 || result.payload[1] != 0x0a ||
        result.payload[2] != 0x0a || result.payload[3] != 0x0a ||
        result.payload[4] != 0x0a || result.payload[5] != 8 ||
        memcmp(result.payload + 6, "\x00\x00\x00\x00\x89\xab\xcd\xef", 8) != 0 ||
        result.payload[14] != 8 ||
        memcmp(result.payload + 15, "\xff\xff\xff\xff\x76\x54\x32\x10", 8) != 0)
        return 1;
    if (udp_probe_classify(80, version_negotiation,
                           sizeof(version_negotiation), cookie) != PROTO_QUIC)
        return 1;
    memcpy(invalid, version_negotiation, sizeof(invalid));
    invalid[1] = 1;
    if (udp_probe_classify(80, invalid, sizeof(invalid), cookie) != PROTO_NONE)
        return 1;
    memcpy(invalid, version_negotiation, sizeof(invalid));
    invalid[6] ^= 1;
    if (udp_probe_classify(80, invalid, sizeof(invalid), cookie) != PROTO_NONE)
        return 1;
    if (udp_probe_classify(80, version_negotiation,
                           sizeof(version_negotiation) - 1, cookie) != PROTO_NONE)
        return 1;
    for (i = 0; i < 27; i++) {
        if (udp_probe_classify(80, version_negotiation, i, cookie) != PROTO_NONE)
            return 1;
    }
    for (i = 0x80; i <= 0xff; i++) {
        memcpy(invalid, version_negotiation, sizeof(invalid));
        invalid[0] = (unsigned char)i;
        if (udp_probe_classify(80, invalid, 27, cookie) != PROTO_QUIC)
            return 1;
    }
    memcpy(invalid, version_negotiation, sizeof(invalid));
    invalid[0] = 0x40;
    if (udp_probe_classify(80, invalid, sizeof(invalid), cookie) != PROTO_NONE)
        return 1;
    memcpy(invalid, version_negotiation, sizeof(invalid));
    invalid[15] ^= 1;
    if (udp_probe_classify(80, invalid, sizeof(invalid), cookie) != PROTO_NONE)
        return 1;
    memcpy(invalid, version_negotiation, sizeof(invalid));
    memset(invalid + 23, 0, 4);
    if (udp_probe_classify(80, invalid, sizeof(invalid), cookie) != PROTO_NONE)
        return 1;

    if (udp_probe_prepare(6969, cookie, NULL, &result) == 0)
        return 1;
    if (result.port != 6969 || result.length != 16 ||
        memcmp(result.payload,
               "\x00\x00\x04\x17\x27\x10\x19\x80"
               "\x00\x00\x00\x00\x89\xab\xcd\xef", 16) != 0)
        return 1;
    if (udp_probe_classify(6969, tracker_response,
                           sizeof(tracker_response), cookie) != PROTO_BITTORRENT)
        return 1;
    memcpy(invalid, tracker_response, sizeof(tracker_response));
    memset(invalid + sizeof(tracker_response), 0xa5,
           sizeof(invalid) - sizeof(tracker_response));
    if (udp_probe_classify(6969, invalid, sizeof(invalid), cookie) != PROTO_BITTORRENT)
        return 1;
    invalid[4] ^= 1;
    if (udp_probe_classify(6969, invalid, sizeof(invalid), cookie) != PROTO_NONE)
        return 1;
    invalid[4] ^= 1;
    invalid[3] = 3;
    if (udp_probe_classify(6969, invalid, sizeof(invalid), cookie) != PROTO_NONE)
        return 1;
    tracker_response[4] ^= 1;
    if (udp_probe_classify(6969, tracker_response,
                           sizeof(tracker_response), cookie) != PROTO_NONE)
        return 1;
    tracker_response[4] ^= 1;
    for (i = 0; i < 16; i++) {
        if (udp_probe_classify(6969, tracker_response, i, cookie) != PROTO_NONE)
            return 1;
    }

    return 0;
}
