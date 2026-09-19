#include "proto-udp-ecom.h"
#include <stdio.h>
#include <string.h>

/* HAP discovery framing: https://hosteng.com/Ethernet_SDK/Solaris.zip
 * The supported response profile has a 15-byte payload, including a bounded
 * six-byte extension. The application value is echoed outside CRC coverage. */
static unsigned
ecom_application_value(uint64_t cookie)
{
    unsigned value = (unsigned)cookie & 0xffff;
    return value ? value : 1;
}

static unsigned
ecom_payload_crc(const unsigned char *data, unsigned length)
{
    unsigned crc = 0, i, bit;
    for (i = 0; i < length; i++) {
        crc ^= (unsigned)data[i] << 8;
        for (bit = 0; bit < 8; bit++)
            crc = ((crc << 1) ^ ((crc & 0x8000) ? 0x1021 : 0)) & 0xffff;
    }
    return crc;
}

int
ecom_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                   struct UdpPreparedProbe *result)
{
    unsigned value = ecom_application_value(cookie);
    (void)target;
    if (!result)
        return 0;
    memcpy(result->payload, "HAP\x00\x00\xa5\x50\x01\x00\x05", 10);
    result->payload[3] = (unsigned char)value;
    result->payload[4] = (unsigned char)(value >> 8);
    result->length = 10;
    return 1;
}

int
ecom_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned value, crc, i, hardware_address = 0;
    if (!data || length != 24 || memcmp(data, "HAP", 3))
        return 0;
    value = (unsigned)data[3] | ((unsigned)data[4] << 8);
    if (value != ecom_application_value(cookie) || data[7] != 15 || data[8] ||
        data[9] != 0x55 || data[10] != 0xaa || data[17] > 1)
        return 0;
    crc = (unsigned)data[5] | ((unsigned)data[6] << 8);
    if (crc != ecom_payload_crc(data + 9, 15) || (data[11] & 1))
        return 0;
    for (i = 11; i < 17; i++)
        hardware_address |= data[i];
    return hardware_address != 0;
}

int
ecom_selftest(void)
{
    static const unsigned char query[] =
        "\x48\x41\x50\x01\x00\xa5\x50\x01\x00\x05";
    static const unsigned char response[] =
        "\x48\x41\x50\x01\x00\x40\x73\x0f\x00\x55\xaa"
        "\x00\xe0\x62\x20\xa1\x32\x00\x01\xc0\xa8\x01\x28\x00";
    static const struct {
        const char *name;
        unsigned offset, value, crc;
        int accepted;
    } mutations[] = {
        {"query response marker", 9, 0x56, 0x9065, 0},
        {"uninitialized address", 17, 1, 0xcb21, 1},
        {"address status boundary", 17, 2, 0x13a3, 0},
        {"multicast hardware address", 11, 1, 0x3623, 0},
        {"opaque payload extension", 23, 0x5a, 0x88ff, 1}
    };
    struct UdpPreparedProbe probe;
    unsigned char changed[25];
    unsigned i, failures = 0;

    memset(&probe, 0, sizeof(probe));

#define ECOM_CHECK(condition, name) do { \
    if (!(condition)) { \
        fprintf(stderr, "ECOM selftest failed: %s\n", name); \
        failures++; \
    } \
} while (0)

    ECOM_CHECK(ecom_probe_prepare(1, 0, &probe), "prepare discovery");
    ECOM_CHECK(probe.length == sizeof(query) - 1 &&
               !memcmp(probe.payload, query, sizeof(query) - 1),
               "discovery wire request");
    ECOM_CHECK(ecom_probe_prepare(0, 0, &probe) &&
               !memcmp(probe.payload, query, sizeof(query) - 1),
               "zero application value normalization");
    ECOM_CHECK(ecom_probe_prepare(UINT64_C(0x123456780000a1b2), 0, &probe) &&
               probe.payload[3] == 0xb2 && probe.payload[4] == 0xa1,
               "application value little endian");
    ECOM_CHECK(!ecom_probe_prepare(1, 0, 0), "missing output buffer");
    ECOM_CHECK(ecom_probe_classify(response, sizeof(response) - 1, 1),
               "complete discovery response");
    ECOM_CHECK(ecom_probe_classify(response, sizeof(response) - 1, 0),
               "normalized response association");
    ECOM_CHECK(!ecom_probe_classify(response, sizeof(response) - 1, 2),
               "wrong application value");
    ECOM_CHECK(!ecom_probe_classify(0, 24, 1), "missing response buffer");
    for (i = 0; i < sizeof(response) - 1; i++)
        ECOM_CHECK(!ecom_probe_classify(response, i, 1), "truncated response");
    memcpy(changed, response, sizeof(response) - 1);
    changed[24] = 0;
    ECOM_CHECK(!ecom_probe_classify(changed, sizeof(changed), 1),
               "unsupported response extension");
    changed[5] ^= 1;
    ECOM_CHECK(!ecom_probe_classify(changed, 24, 1), "wrong payload CRC");
    changed[5] ^= 1;
    changed[7]--;
    ECOM_CHECK(!ecom_probe_classify(changed, 24, 1), "wrong payload length");
    changed[7]++;
    changed[8] = 1;
    ECOM_CHECK(!ecom_probe_classify(changed, 24, 1), "oversized payload length");
    changed[8] = 0;
    changed[2] = 'A';
    ECOM_CHECK(!ecom_probe_classify(changed, 24, 1), "unsupported HAA framing");
    ECOM_CHECK(!ecom_probe_classify(query, sizeof(query) - 1, 1),
               "request is not a response");
    for (i = 0; i < sizeof(mutations) / sizeof(mutations[0]); i++) {
        memcpy(changed, response, sizeof(response) - 1);
        changed[mutations[i].offset] = (unsigned char)mutations[i].value;
        changed[5] = (unsigned char)mutations[i].crc;
        changed[6] = (unsigned char)(mutations[i].crc >> 8);
        ECOM_CHECK(ecom_probe_classify(changed, 24, 1) == mutations[i].accepted,
                   mutations[i].name);
    }
    memcpy(changed, response, sizeof(response) - 1);
    memset(changed + 11, 0, 6);
    changed[5] = 0x07;
    changed[6] = 0x27;
    ECOM_CHECK(!ecom_probe_classify(changed, 24, 1), "empty hardware address");
#undef ECOM_CHECK
    return failures != 0;
}
