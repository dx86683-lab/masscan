#include "proto-udp-citrix.h"
#include <stdio.h>
#include <string.h>

int
citrix_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                     struct UdpPreparedProbe *result)
{
    static const unsigned char request[] = {
        0x2a, 0, 1, 0x32, 2, 0xfd, 0xa8, 0xe3,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0x21, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    (void)cookie;
    (void)target;
    memcpy(result->payload, request, sizeof(request));
    result->length = sizeof(request);
    return 1;
}

int
citrix_probe_classify(const unsigned char *px, unsigned length, uint64_t cookie)
{
    static const unsigned char response_profile[] = {
        4, 0x33, 2, 0xfd, 0xa8, 0xe3
    };
    unsigned offset = 40;
    (void)cookie;
    /* The list layout is documented by the Nmap script author. Restrict the
     * header profile to the independently published reply, without assigning
     * semantics to the remaining bytes within its fixed 40-byte header. */
    if (length < 40 || length > 65535)
        return 0;
    if (((unsigned)px[0] | (unsigned)px[1] << 8) != length
        || memcmp(px + 2, response_profile, sizeof(response_profile))
        || px[30] > 1)
        return 0;
    /* A final response can contain a complete header and no applications. */
    if (length == 40)
        return px[30] == 1;

    /* Application names are NUL-terminated byte strings; their encoding is
     * not interpreted. A more flag of zero still identifies one complete
     * datagram; no reassembly or follow-up query is needed for identification. */
    while (offset < length) {
        unsigned start = offset;
        while (offset < length && px[offset]) {
            offset++;
        }
        if (offset == start || offset == length)
            return 0;
        offset++;
    }
    return 1;
}

/* Complete published application-list datagram, with more packets following:
 * https://github.com/Phenomite/AMP-Research/tree/master/Port%201604%20-%20Citrix
 * Header/strings: https://nmap.org/nsedoc/scripts/citrix-enum-apps.html
 * The hex payload and its declared length both contain 475 bytes.
 */
static const unsigned char citrix_list_fixture[] = {
    0xdb, 0x01, 0x04, 0x33, 0x02, 0xfd, 0xa8, 0xe3, 0x02, 0x00, 0x06, 0x44,
    0x45, 0xa4, 0x98, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x28, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x31, 0x37, 0x30, 0x30, 0x20, 0x4a, 0x52, 0x20,
    0x44, 0x65, 0x6d, 0x6f, 0x00, 0x32, 0x34, 0x20, 0x53, 0x65, 0x76, 0x65,
    0x6e, 0x20, 0x42, 0x72, 0x61, 0x6e, 0x64, 0x73, 0x20, 0x52, 0x75, 0x6e,
    0x69, 0x74, 0x35, 0x30, 0x20, 0x53, 0x51, 0x4c, 0x00, 0x32, 0x36, 0x31,
    0x30, 0x31, 0x20, 0x42, 0x6f, 0x74, 0x61, 0x73, 0x20, 0x43, 0x75, 0x61,
    0x64, 0x72, 0x61, 0x20, 0x55, 0x53, 0x41, 0x20, 0x2d, 0x20, 0x55, 0x53,
    0x41, 0x00, 0x32, 0x36, 0x31, 0x30, 0x31, 0x20, 0x42, 0x6f, 0x74, 0x61,
    0x73, 0x20, 0x43, 0x75, 0x61, 0x64, 0x72, 0x61, 0x20, 0x55, 0x53, 0x41,
    0x20, 0x2d, 0x20, 0x6d, 0x65, 0x78, 0x69, 0x63, 0x6f, 0x00, 0x32, 0x36,
    0x31, 0x30, 0x31, 0x20, 0x42, 0x6f, 0x74, 0x61, 0x73, 0x20, 0x43, 0x75,
    0x61, 0x64, 0x72, 0x61, 0x20, 0x55, 0x53, 0x41, 0x20, 0x52, 0x75, 0x6e,
    0x69, 0x74, 0x35, 0x30, 0x20, 0x53, 0x51, 0x4c, 0x00, 0x32, 0x36, 0x31,
    0x30, 0x31, 0x20, 0x57, 0x65, 0x62, 0x69, 0x74, 0x00, 0x32, 0x37, 0x37,
    0x35, 0x20, 0x56, 0x6f, 0x6c, 0x6c, 0x61, 0x6e, 0x74, 0x65, 0x20, 0x52,
    0x75, 0x6e, 0x69, 0x74, 0x35, 0x30, 0x20, 0x53, 0x51, 0x4c, 0x00, 0x32,
    0x38, 0x30, 0x30, 0x31, 0x20, 0x53, 0x61, 0x6d, 0x62, 0x61, 0x20, 0x32,
    0x20, 0x52, 0x75, 0x6e, 0x69, 0x74, 0x35, 0x30, 0x20, 0x53, 0x51, 0x4c,
    0x00, 0x32, 0x38, 0x30, 0x30, 0x31, 0x20, 0x53, 0x61, 0x6d, 0x62, 0x61,
    0x20, 0x32, 0x20, 0x55, 0x74, 0x69, 0x6c, 0x65, 0x72, 0x69, 0x61, 0x73,
    0x00, 0x32, 0x39, 0x38, 0x30, 0x53, 0x69, 0x78, 0x74, 0x79, 0x20, 0x46,
    0x61, 0x63, 0x74, 0x75, 0x72, 0x61, 0x63, 0x69, 0x6f, 0x6e, 0x20, 0x33,
    0x5f, 0x33, 0x00, 0x32, 0x39, 0x38, 0x30, 0x53, 0x69, 0x78, 0x74, 0x79,
    0x20, 0x52, 0x75, 0x6e, 0x69, 0x74, 0x35, 0x30, 0x73, 0x71, 0x6c, 0x00,
    0x32, 0x39, 0x38, 0x39, 0x31, 0x30, 0x20, 0x43, 0x6c, 0x6f, 0x65, 0x20,
    0x4d, 0x69, 0x61, 0x6d, 0x69, 0x20, 0x52, 0x75, 0x6e, 0x69, 0x74, 0x35,
    0x30, 0x20, 0x53, 0x51, 0x4c, 0x00, 0x32, 0x39, 0x38, 0x39, 0x31, 0x30,
    0x20, 0x43, 0x6c, 0x6f, 0x65, 0x20, 0x4d, 0x69, 0x61, 0x6d, 0x69, 0x20,
    0x55, 0x74, 0x69, 0x6c, 0x65, 0x72, 0x69, 0x61, 0x73, 0x00, 0x32, 0x39,
    0x38, 0x39, 0x33, 0x20, 0x43, 0x6c, 0x6f, 0x65, 0x20, 0x52, 0x75, 0x6e,
    0x69, 0x74, 0x35, 0x30, 0x20, 0x53, 0x51, 0x4c, 0x00, 0x32, 0x39, 0x38,
    0x39, 0x33, 0x20, 0x43, 0x6c, 0x6f, 0x65, 0x20, 0x55, 0x74, 0x69, 0x6c,
    0x65, 0x72, 0x69, 0x61, 0x73, 0x00, 0x32, 0x39, 0x38, 0x39, 0x34, 0x20,
    0x43, 0x6c, 0x6f, 0x65, 0x20, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x73, 0x20,
    0x46, 0x61, 0x63, 0x74, 0x75, 0x72, 0x61, 0x63, 0x69, 0x6f, 0x6e, 0x45,
    0x00, 0x32, 0x39, 0x38, 0x39, 0x34, 0x20, 0x43, 0x6c, 0x6f, 0x65, 0x20,
    0x53, 0x74, 0x6f, 0x72, 0x65, 0x73, 0x20, 0x52, 0x75, 0x6e, 0x69, 0x74,
    0x35, 0x30, 0x20, 0x53, 0x51, 0x4c, 0x00,
};

int
citrix_selftest(void)
{
    static const unsigned char expected_request[] = {
        0x2a, 0, 1, 0x32, 2, 0xfd, 0xa8, 0xe3,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0x21, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    struct UdpPreparedProbe probe;
    unsigned char altered[sizeof(citrix_list_fixture) + 1];
    unsigned i;
    int failures = 0;
#define CHECK_CITRIX(condition, name) do { \
    if (!(condition)) { \
        fprintf(stderr, "citrix selftest: %s\n", name); \
        failures++; \
    } \
} while (0)

    {
        static const unsigned char empty_final[] =
            "\x28\x00\x04\x33\x02\xfd\xa8\xe3\x02\x00\x06\x44"
            "\xc0\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00";
        /* A complete empty final list has only its 40-byte header. */
        CHECK_CITRIX(citrix_probe_classify(empty_final, sizeof(empty_final) - 1, 0),
                     "complete empty final application list");
        for (i = 0; i < sizeof(empty_final) - 1; i++)
            CHECK_CITRIX(!citrix_probe_classify(empty_final, i, 0),
                         "truncated empty application list");
        memcpy(altered, empty_final, sizeof(empty_final));
        altered[0] = 39;
        CHECK_CITRIX(!citrix_probe_classify(altered, 40, 0), "empty list short declared length");
        altered[0] = 41;
        CHECK_CITRIX(!citrix_probe_classify(altered, 40, 0), "empty list long declared length");
        CHECK_CITRIX(!citrix_probe_classify(altered, 41, 0), "empty trailing name is not an empty list");
        altered[0] = 40; altered[30] = 0;
        CHECK_CITRIX(!citrix_probe_classify(altered, 40, 0), "unsupported empty continuation");
        altered[30] = 2;
        CHECK_CITRIX(!citrix_probe_classify(altered, 40, 0), "empty list invalid final flag");
        altered[30] = 1; altered[3] = 0x32;
        CHECK_CITRIX(!citrix_probe_classify(altered, 40, 0), "empty list wrong response type");
    }
    {
        /* Complete captured byte-string response; names and address anonymized. */
        static const unsigned char byte_names[] =
            "\x9a\x00\x04\x33\x02\xfd\xa8\xe3\x02\x00\x06\x44\xc0\x00\x02\x01"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00"
            "\x05\x00\x28\x00\x00\x00\x00\x00\x41\x41\x41\x41\x41\x41\x41\x41"
            "\x41\x41\x41\x41\xf3\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x41\x41\x41\x41"
            "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x41\x41\x41"
            "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00"
            "\x41\x41\x41\x41\x41\x41\x41\x00\x41\x41\x41\x41\x41\x41\x41\x41"
            "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00";
        CHECK_CITRIX(citrix_probe_classify(byte_names, sizeof(byte_names) - 1, 0),
                     "complete byte-string application list");
    }
    memset(&probe, 0, sizeof(probe));
    CHECK_CITRIX(citrix_probe_prepare(0x12345678, 0, &probe),
                 "application-list request preparation");
    CHECK_CITRIX(probe.length == sizeof(expected_request)
                 && !memcmp(probe.payload, expected_request, sizeof(expected_request)),
                 "application-list wire request");
    CHECK_CITRIX(citrix_probe_classify(citrix_list_fixture,
                    sizeof(citrix_list_fixture), 0x12345678),
                 "published complete datagram with continuation");
    /* Transaction mismatch is not applicable: this query has no documented
     * randomized transaction field. Cookie changes must not alter recognition. */
    CHECK_CITRIX(citrix_probe_classify(citrix_list_fixture,
                    sizeof(citrix_list_fixture), 0x87654321),
                 "no invented transaction correlation");
    CHECK_CITRIX(!citrix_probe_classify(0, 0, 0), "empty datagram");
    CHECK_CITRIX(!citrix_probe_classify(expected_request,
                    sizeof(expected_request), 0), "request echo");
    memset(altered, 0x41, sizeof(altered));
    CHECK_CITRIX(!citrix_probe_classify(altered, sizeof(altered), 0),
                 "unrelated datagram");
    for (i = 0; i < sizeof(citrix_list_fixture); i++) {
        if (citrix_probe_classify(citrix_list_fixture, i, 0)) {
            CHECK_CITRIX(0, "truncated published datagram");
            break;
        }
    }
    memcpy(altered, citrix_list_fixture, sizeof(citrix_list_fixture));
    altered[0]++;
    CHECK_CITRIX(!citrix_probe_classify(altered, sizeof(citrix_list_fixture), 0),
                 "declared size exceeds datagram");
    altered[0] -= 2;
    CHECK_CITRIX(!citrix_probe_classify(altered, sizeof(citrix_list_fixture), 0),
                 "declared size smaller than datagram");
    for (i = 2; i < 8; i++) {
        memcpy(altered, citrix_list_fixture, sizeof(citrix_list_fixture));
        altered[i] ^= 1;
        CHECK_CITRIX(!citrix_probe_classify(altered, sizeof(citrix_list_fixture), 0),
                     "unsupported header profile or signature");
    }
    memcpy(altered, citrix_list_fixture, sizeof(citrix_list_fixture));
    altered[30] = 1;
    CHECK_CITRIX(citrix_probe_classify(altered, sizeof(citrix_list_fixture), 0),
                 "last-datagram flag");
    altered[30] = 2;
    CHECK_CITRIX(!citrix_probe_classify(altered, sizeof(citrix_list_fixture), 0),
                 "invalid continuation flag");
    memcpy(altered, citrix_list_fixture, sizeof(citrix_list_fixture));
    altered[16] = 0xff;
    CHECK_CITRIX(citrix_probe_classify(altered, sizeof(citrix_list_fixture), 0),
                 "opaque header bytes do not become invented reserved fields");
    memcpy(altered, citrix_list_fixture, sizeof(citrix_list_fixture));
    altered[sizeof(citrix_list_fixture) - 1] = 'X';
    CHECK_CITRIX(!citrix_probe_classify(altered, sizeof(citrix_list_fixture), 0),
                 "unterminated final name");
    memcpy(altered, citrix_list_fixture, sizeof(citrix_list_fixture));
    altered[0]++;
    altered[sizeof(citrix_list_fixture)] = 'X';
    CHECK_CITRIX(!citrix_probe_classify(altered, sizeof(altered), 0),
                 "unterminated trailing name");
    altered[sizeof(citrix_list_fixture)] = 0;
    CHECK_CITRIX(!citrix_probe_classify(altered, sizeof(altered), 0),
                 "trailing empty name");
    memcpy(altered, citrix_list_fixture, sizeof(citrix_list_fixture));
    altered[40] = 0;
    CHECK_CITRIX(!citrix_probe_classify(altered, sizeof(citrix_list_fixture), 0),
                 "empty first name");
    altered[40] = 0x1b;
    CHECK_CITRIX(citrix_probe_classify(altered, sizeof(citrix_list_fixture), 0),
                 "opaque name byte is not interpreted as text");
    altered[40] = 0x80;
    CHECK_CITRIX(citrix_probe_classify(altered, sizeof(citrix_list_fixture), 0),
                 "high-bit name byte is encoding independent");
    memcpy(altered, citrix_list_fixture, 40);
    altered[0] = 40;
    altered[1] = 0;
    CHECK_CITRIX(!citrix_probe_classify(altered, 40, 0), "empty name area");
#undef CHECK_CITRIX
    return failures != 0;
}
