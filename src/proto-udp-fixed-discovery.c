#include "proto-udp-fixed-discovery.h"
#include <string.h>

static unsigned
sbus_crc(const unsigned char *data, unsigned length)
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
sbus_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                   struct UdpPreparedProbe *result)
{
    unsigned crc;
    (void)target;
    memcpy(result->payload, "\x00\x00\x00\x0d\x00\x00\x00\x00\x00\xff\x1d", 11);
    result->payload[6] = (unsigned char)(cookie >> 8);
    result->payload[7] = (unsigned char)cookie;
    crc = sbus_crc(result->payload, 11);
    result->payload[11] = (unsigned char)(crc >> 8);
    result->payload[12] = (unsigned char)crc;
    result->length = 13;
    return 1;
}

int
sbus_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    return length == 12 && !memcmp(data, "\x00\x00\x00\x0c\x00\x00", 6) &&
        data[6] == (unsigned char)(cookie >> 8) && data[7] == (unsigned char)cookie &&
        data[8] == 1 && data[9] != 255 &&
        sbus_crc(data, 10) == ((unsigned)data[10] << 8 | data[11]);
}

int
lantronix_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                        struct UdpPreparedProbe *result)
{
    (void)cookie; (void)target;
    memcpy(result->payload, "\x00\x00\x00\xf6", 4);
    result->length = 4;
    return 1;
}

int
lantronix_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned i, used = 0;
    (void)cookie;
    if (length != 30 || memcmp(data, "\x00\x00\x00\xf7", 4) || (data[24] & 1)) return 0;
    for (i = 24; i < 30; i++) used |= data[i];
    return used != 0;
}

int
db2_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                  struct UdpPreparedProbe *result)
{
    (void)cookie; (void)target;
    memcpy(result->payload, "DB2GETADDR\x00" "SQL09010\x00", 20);
    result->length = 20;
    return 1;
}

int
db2_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned i;
    (void)cookie;
    if (length < 22 || length > 276 || memcmp(data, "DB2RETADDR\x00" "SQL", 14) ||
        data[19] || data[length - 1]) return 0;
    for (i = 14; i < 19; i++) if (data[i] < '0' || data[i] > '9') return 0;
    for (i = 20; i < length - 1; i++) {
        unsigned c = data[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) return 0;
    }
    return 1;
}

int
moxa_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                   struct UdpPreparedProbe *result)
{
    (void)cookie; (void)target;
    memcpy(result->payload, "\x01\x00\x00\x08\x00\x00\x00\x00", 8);
    result->length = 8;
    return 1;
}

int
moxa_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    (void)cookie;
    return length == 24 && data[0] == 0x81 && data[1] != 4 && data[3] == 24 &&
        !memcmp(data + 14, "\x00\x90\xe8", 3);
}
