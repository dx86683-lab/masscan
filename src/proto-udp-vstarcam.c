#include "proto-udp-vstarcam.h"
#include <stdio.h>
#include <string.h>

/* CSearchDVS in the vendor Android SDK uses DH/0x0101 for read-only
 * discovery and DH/0x0801 for its network-parameter reply (little endian).
 * https://github.com/vstarcam/as_cam/tree/5eb4bc7361d4375cf4d9b70cb6754cb2796043f2
 * This profile accepts only the complete 524-byte layout independently
 * captured with firmware 66.81.204.19. Other lengths remain unclassified.
 * No request transaction field exists in this discovery exchange. */
int
vstarcam_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                       struct UdpPreparedProbe *result)
{
    (void)cookie;
    if (!result) return 0;
    result->length = 0;
    if (!target || target->source_port != 8601 ||
        target->source.version != 4 || target->destination.version != 4)
        return 0;
    memcpy(result->payload, "\x44\x48\x01\x01", 4);
    result->length = 4;
    return 1;
}

static unsigned
vstarcam_string_length(const unsigned char *data, unsigned size)
{
    unsigned i;
    for (i = 0; i < size; i++) if (!data[i]) return i;
    return 0;
}

static int
vstarcam_decimal_fields(const unsigned char *data, unsigned length, unsigned maximum)
{
    unsigned i, fields = 0, digits = 0, value = 0;
    if (!length) return 0;
    for (i = 0; i <= length; i++) {
        if (i == length || data[i] == '.') {
            if (!digits || value > maximum) return 0;
            fields++;
            digits = value = 0;
        } else {
            if (data[i] < '0' || data[i] > '9' || ++digits > 3) return 0;
            value = value * 10 + data[i] - '0';
        }
    }
    return fields == 4;
}

static int
vstarcam_name(const unsigned char *data, unsigned length)
{
    unsigned i = 0;
    if (!length) return 0;
    while (i < length) {
        unsigned c = data[i++], codepoint, continuation, minimum;
        if (c < 0x80) {
            if (c < 0x20 || c == 0x7f) return 0;
            continue;
        }
        if (c >= 0xc2 && c <= 0xdf) {
            codepoint = c & 0x1f; continuation = 1; minimum = 0x80;
        } else if (c >= 0xe0 && c <= 0xef) {
            codepoint = c & 0x0f; continuation = 2; minimum = 0x800;
        } else if (c >= 0xf0 && c <= 0xf4) {
            codepoint = c & 7; continuation = 3; minimum = 0x10000;
        } else return 0;
        if (continuation > length - i) return 0;
        while (continuation--) {
            c = data[i++];
            if ((c & 0xc0) != 0x80) return 0;
            codepoint = (codepoint << 6) | (c & 0x3f);
        }
        if (codepoint < minimum || codepoint > 0x10ffff ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff)) return 0;
    }
    return 1;
}

int
vstarcam_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned i, nonzero = 0;
    (void)cookie;
    if (!data || length != 524 || memcmp(data, "\x44\x48\x01\x08", 4)) return 0;
    /* Five independent 16-byte IPv4 strings occupy [4,84). */
    for (i = 4; i < 84; i += 16)
        if (!vstarcam_decimal_fields(data + i, vstarcam_string_length(data + i, 16), 255))
            return 0;
    for (i = 84; i < 90; i++) nonzero |= data[i];
    if (!nonzero || (data[84] & 1) || !(data[90] | data[91])) return 0;
    /* Observed device-ID grammar: four letters, six digits, five letters;
     * the containing field is 32 bytes. The following name starts at 124. */
    if (vstarcam_string_length(data + 92, 32) != 15) return 0;
    for (i = 0; i < 15; i++) {
        unsigned c = data[92 + i];
        if (i >= 4 && i < 10) {
            if (c < '0' || c > '9') return 0;
        } else if (c < 'A' || c > 'Z') return 0;
    }
    if (!vstarcam_name(data + 124, vstarcam_string_length(data + 124, 32)) ||
        !vstarcam_decimal_fields(data + 204, vstarcam_string_length(data + 204, 16), 999))
        return 0;
    /* [156,204) and [220,524) are bounded opaque fields, including mode
     * and extensions. Uninterpreted bytes are not required to be zero. */
    return 1;
}

int
vstarcam_selftest(void)
{
    /* Sanitized full UDP fixture; original firmware 66.81.204.19.
     * Public capture: github.com/NosefU/vstarcam_cam_finder at
     * 674522ef52e73fd91a5ff2fbdbdfde1dae479d0a, frames 9 and 10.
     * Original payload SHA256:
     * f1a3da175183c984cadb9ebef515366e4cdbd1c466b7105d0a9585658a1b3f5f.
     * Addresses, device identity, label and opaque suffix are anonymized. */
    static const unsigned char fixture[524] = {
        0x44, 0x48, 0x01, 0x08, 0x31, 0x39, 0x32, 0x2e, 0x30, 0x2e, 0x32, 0x2e, 0x32, 0x30, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x32, 0x35, 0x35, 0x2e, 0x32, 0x35, 0x35, 0x2e, 0x32, 0x35, 0x35, 0x2e,
        0x30, 0x00, 0x00, 0x00, 0x31, 0x39, 0x32, 0x2e, 0x30, 0x2e, 0x32, 0x2e, 0x31, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x32, 0x30, 0x33, 0x2e, 0x30, 0x2e, 0x31, 0x31, 0x33, 0x2e, 0x35, 0x33,
        0x00, 0x00, 0x00, 0x00, 0x32, 0x30, 0x33, 0x2e, 0x30, 0x2e, 0x31, 0x31, 0x33, 0x2e, 0x35, 0x33,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0xa0, 0x46, 0x54, 0x45, 0x53, 0x54,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x41, 0x42, 0x43, 0x44, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x61, 0x62, 0x20,
        0x63, 0x61, 0x6d, 0x65, 0x72, 0x61, 0x20, 0xe7, 0x9b, 0xb8, 0xe6, 0x9c, 0xba, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x36, 0x2e, 0x38,
        0x31, 0x2e, 0x32, 0x30, 0x34, 0x2e, 0x31, 0x39, 0x00, 0x00, 0x00, 0x00, 0x76, 0x61, 0x72, 0x20,
        0x61, 0x70, 0x70, 0x5f, 0x76, 0x65, 0x72, 0x3d, 0x22, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    static const unsigned address_offsets[] = {4, 20, 36, 52, 68};
    unsigned char changed[525];
    struct UdpPreparedProbe result;
    struct UdpProbeTarget target;
    unsigned i, j, failures = 0;
#define VSTARCAM_CHECK(condition, label) do { \
    if (!(condition)) { \
        fprintf(stderr, "VStarcam selftest: %s\n", label); \
        failures++; \
    } \
} while (0)
    memset(&target, 0, sizeof(target));
    target.source.version = target.destination.version = 4;
    target.source_port = 8601;
    memset(&result, 0, sizeof(result));
    VSTARCAM_CHECK(vstarcam_probe_prepare(123, &target, &result) &&
                   result.length == 4 && !memcmp(result.payload, "\x44\x48\x01\x01", 4),
                   "prepare read-only discovery request");
    target.source_port = 40000;
    VSTARCAM_CHECK(!vstarcam_probe_prepare(123, &target, &result), "reject unsupported source port");
    VSTARCAM_CHECK(!vstarcam_probe_prepare(123, NULL, &result), "require source-port context");
    target.source_port = 8601;
    target.destination.version = 6;
    VSTARCAM_CHECK(!vstarcam_probe_prepare(123, &target, &result), "reject unsupported address family");
    VSTARCAM_CHECK(vstarcam_probe_classify(fixture, sizeof(fixture), 123), "accept complete captured layout");
    VSTARCAM_CHECK(vstarcam_probe_classify(fixture, sizeof(fixture), 456), "transaction ID not applicable");
    for (i = 0; i < sizeof(fixture); i++)
        VSTARCAM_CHECK(!vstarcam_probe_classify(fixture, i, 123), "reject every truncated response");
    memcpy(changed, fixture, sizeof(fixture));
    changed[524] = 0;
    VSTARCAM_CHECK(!vstarcam_probe_classify(changed, sizeof(changed), 123), "reject unproved longer layout");
    for (i = 0; i < 4; i++) {
        memcpy(changed, fixture, sizeof(fixture));
        changed[i] ^= 1;
        VSTARCAM_CHECK(!vstarcam_probe_classify(changed, sizeof(fixture), 123), "reject unrelated header or request echo");
    }
    for (i = 0; i < sizeof(address_offsets) / sizeof(address_offsets[0]); i++) {
        memcpy(changed, fixture, sizeof(fixture));
        memset(changed + address_offsets[i], '1', 16);
        VSTARCAM_CHECK(!vstarcam_probe_classify(changed, sizeof(fixture), 123), "reject unterminated address field");
        memcpy(changed, fixture, sizeof(fixture));
        memcpy(changed + address_offsets[i], "999.1.1.1\0", 10);
        VSTARCAM_CHECK(!vstarcam_probe_classify(changed, sizeof(fixture), 123), "reject out-of-range IPv4 octet");
    }
    memcpy(changed, fixture, sizeof(fixture));
    memset(changed + 84, 0, 6);
    VSTARCAM_CHECK(!vstarcam_probe_classify(changed, sizeof(fixture), 123), "reject zero MAC");
    changed[84] = 1;
    VSTARCAM_CHECK(!vstarcam_probe_classify(changed, sizeof(fixture), 123), "reject multicast MAC");
    memcpy(changed, fixture, sizeof(fixture));
    changed[90] = changed[91] = 0;
    VSTARCAM_CHECK(!vstarcam_probe_classify(changed, sizeof(fixture), 123), "reject zero service port");
    for (i = 92; i < 107; i++) {
        memcpy(changed, fixture, sizeof(fixture));
        changed[i] = '!';
        VSTARCAM_CHECK(!vstarcam_probe_classify(changed, sizeof(fixture), 123), "reject malformed device identifier");
    }
    memcpy(changed, fixture, sizeof(fixture));
    changed[107] = 'A';
    VSTARCAM_CHECK(!vstarcam_probe_classify(changed, sizeof(fixture), 123), "reject overlength device identifier");
    memcpy(changed, fixture, sizeof(fixture));
    memset(changed + 124, 'A', 32);
    VSTARCAM_CHECK(!vstarcam_probe_classify(changed, sizeof(fixture), 123), "reject unterminated camera name");
    changed[155] = 0;
    VSTARCAM_CHECK(vstarcam_probe_classify(changed, sizeof(fixture), 123), "accept maximum bounded camera name");
    changed[124] = 0;
    VSTARCAM_CHECK(!vstarcam_probe_classify(changed, sizeof(fixture), 123), "reject empty camera name");
    for (i = 0; i < 3; i++) {
        static const unsigned char bad_utf8[3][4] = {{0xc0, 0xaf, 0, 0}, {0xed, 0xa0, 0x80, 0}, {0xf4, 0x90, 0x80, 0x80}};
        memcpy(changed, fixture, sizeof(fixture));
        memset(changed + 124, 0, 32);
        memcpy(changed + 124, bad_utf8[i], 4);
        VSTARCAM_CHECK(!vstarcam_probe_classify(changed, sizeof(fixture), 123), "reject invalid UTF-8 name");
    }
    for (i = 0; i < 2; i++) {
        memcpy(changed, fixture, sizeof(fixture));
        memset(changed + 204, i ? '1' : 0, 16);
        VSTARCAM_CHECK(!vstarcam_probe_classify(changed, sizeof(fixture), 123), "reject empty or unterminated firmware");
    }
    memcpy(changed, fixture, sizeof(fixture));
    changed[206] = '!';
    VSTARCAM_CHECK(!vstarcam_probe_classify(changed, sizeof(fixture), 123), "reject malformed firmware version");
    memcpy(changed, fixture, sizeof(fixture));
    for (j = 156; j < 204; j++) changed[j] = 0xa5;
    for (j = 220; j < 524; j++) changed[j] = 0xa5;
    VSTARCAM_CHECK(vstarcam_probe_classify(changed, sizeof(fixture), 123), "bounded opaque fields are not invented reserved zeros");
#undef VSTARCAM_CHECK
    return failures != 0;
}
