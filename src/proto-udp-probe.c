#include "proto-udp-probe.h"
#include "proto-udp-sip.h"
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

static const struct UdpProbeSpec udp_probe_catalog[] = {
    {80, PROTO_QUIC, quic_prepare, quic_classify},
    {6969, PROTO_BITTORRENT, bittorrent_prepare, bittorrent_classify},
    {64738, PROTO_MUMBLE, mumble_prepare, mumble_classify},
    {2427, PROTO_MGCP, mgcp_prepare, mgcp_classify},
    {6060, PROTO_SIP, sip_probe_prepare, sip_probe_classify},
    {5060, PROTO_SIP, sip_probe_prepare, sip_probe_classify},
    {0, PROTO_NONE, 0, 0}
};

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
