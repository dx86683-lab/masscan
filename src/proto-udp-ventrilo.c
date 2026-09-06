#include "proto-udp-ventrilo.h"
#include "proto-udp-ventrilo-tables.h"
#include <string.h>

static unsigned
ventrilo_u16(const unsigned char *data)
{
    return (unsigned)data[0] << 8 | data[1];
}

static unsigned
ventrilo_crc(const unsigned char *data, unsigned length)
{
    unsigned crc = 0, i, bit;
    for (i = 0; i < length; i++) {
        unsigned table_value = crc & 0xff00;
        for (bit = 0; bit < 8; bit++)
            table_value = ((table_value << 1) ^ ((table_value & 0x8000) ? 0x1021 : 0)) & 0xffff;
        crc = (table_value ^ (crc << 8) ^ data[i]) & 0xffff;
    }
    return crc;
}

int
ventrilo_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                      struct UdpPreparedProbe *result)
{
    unsigned i;
    (void)target;
    memcpy(result->payload, "\x45\x01\x00\x00\x00\x02\x00\x00\x00\x10\x00\x10\x00\x01\x00\x00\x01\x01\x00\x00", 20);
    result->payload[6] = (unsigned char)(cookie >> 8);
    result->payload[7] = (unsigned char)cookie;
    for (i = 0; i < 18; i++)
        result->payload[2 + i] = (unsigned char)(result->payload[2 + i] + VENTRILO_HEADER_TABLE[(0x45 + i) & 255] + i % 5);
    for (i = 0; i < 16; i++)
        result->payload[20 + i] = (unsigned char)(VENTRILO_DATA_TABLE[(1 + i) & 255] + i % 72);
    result->length = 36;
    return 1;
}

int
ventrilo_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned char header[20], body[492];
    unsigned i, size, key, start = 0, seen = 0, lines = 0;
    if (length < 21 || length > 512 || !data[1]) return 0;
    memcpy(header, data, 20);
    for (i = 0; i < 18; i++)
        header[2 + i] = (unsigned char)(data[2 + i] - VENTRILO_HEADER_TABLE[(data[0] + i * data[1]) & 255] - i % 5);
    size = ventrilo_u16(header + 10); key = ventrilo_u16(header + 16);
    if (ventrilo_u16(header + 2) || ventrilo_u16(header + 4) != 2 ||
        ventrilo_u16(header + 6) != (cookie & 0xffff) ||
        !size || size > sizeof(body) || size + 20 != length ||
        ventrilo_u16(header + 8) != size || ventrilo_u16(header + 12) != 1 ||
        ventrilo_u16(header + 14) || !(key & 255)) return 0;
    for (i = 0; i < size; i++)
        body[i] = (unsigned char)(data[20 + i] - VENTRILO_DATA_TABLE[((key >> 8) + i * (key & 255)) & 255] - i % 72);
    if (ventrilo_crc(body, size) != ventrilo_u16(header + 18)) return 0;
    if (!body[size - 1]) size--;
    if (!size || body[size - 1] != '\n') return 0;
    for (i = 0; i < size; i++) {
        if (body[i] == '\n') {
            unsigned end = i, field = 0, prefix = 0, j, nonspace = 0;
            if (++lines > 64) return 0;
            if (end > start && body[end - 1] == '\r') end--;
            if (end - start > 255) return 0;
            if (end - start >= 6 && !memcmp(body + start, "NAME: ", 6)) { field = 1; prefix = 6; }
            else if (end - start >= 9 && !memcmp(body + start, "VERSION: ", 9)) { field = 2; prefix = 9; }
            for (j = start; j < end; j++) if (body[j] < 32 || body[j] > 126) return 0;
            if (field) {
                if (seen & field) return 0;
                for (j = start + prefix; j < end; j++) nonspace |= body[j] != ' ';
                if (!nonspace) return 0;
                seen |= field;
            }
            start = i + 1;
        }
    }
    return seen == 3;
}
