#include "proto-udp-probe.h"
#include "proto-udp-sip.h"
#include "proto-udp-snmpv3.h"
#include "proto-udp-mdns.h"
#include "proto-udp-sqlr.h"
#include "proto-udp-ssdp.h"
#include "proto-udp-openvpn.h"
#include "proto-udp-runtime.h"
#include "proto-udp-dht.h"
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
#ifdef UDP_EXTENDED_PROBES
    {1194, PROTO_OPENVPN, openvpn_probe_prepare, openvpn_probe_classify},
    {6881, PROTO_DHT, dht_probe_prepare, dht_probe_classify},
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
    unsigned i;

    if (response == NULL && response_length != 0)
        return PROTO_NONE;

    for (i = 0; udp_probe_catalog[i].port != 0; i++) {
        if (udp_probe_catalog[i].port != port)
            continue;
        if (udp_probe_catalog[i].classify(response, response_length, cookie))
            return udp_probe_catalog[i].protocol;
        return PROTO_NONE;
    }

    return PROTO_NONE;
}

int
udp_probe_catalog_selftest(void)
{
    struct UdpPreparedProbe result;
    static const uint64_t cookie = UINT64_C(0x0000000089abcdef);
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

#ifdef UDP_EXTENDED_PROBES
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
