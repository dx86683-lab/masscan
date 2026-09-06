#include "proto-udp-structured-discovery.h"
#include <string.h>

static int
discovery_ascii(const unsigned char *data, unsigned length)
{
    unsigned i;
    if (length > 255) return 0;
    for (i = 0; i < length; i++) if (data[i] < 32 || data[i] > 126) return 0;
    return 1;
}

static int
discovery_mac(const unsigned char *data)
{
    unsigned i, used = 0;
    if (data[0] & 1) return 0;
    for (i = 0; i < 6; i++) used |= data[i];
    return used != 0;
}

int
digi_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                   struct UdpPreparedProbe *result)
{
    (void)cookie; (void)target;
    memcpy(result->payload, "DIGI\x00\x01\x00\x06\xff\xff\xff\xff\xff\xff", 14);
    result->length = 14;
    return 1;
}

int
digi_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned offset = 8, mac = 0, identity = 0;
    unsigned char seen[256] = {0};
    (void)cookie;
    if (length < 8 || length > 4096 || memcmp(data, "DIGI\x00\x02", 6) ||
        ((unsigned)data[6] << 8 | data[7]) != length - 8) return 0;
    while (offset < length) {
        unsigned type, size, fixed = 0, text;
        const unsigned char *value;
        if (length - offset < 2) return 0;
        type = data[offset]; size = data[offset + 1]; offset += 2;
        if (size > length - offset) return 0;
        value = data + offset;
        text = type == 4 || type == 5 || type == 8 || type == 9 || type == 13;
        switch (type) {
        case 1: fixed = 6; break;
        case 2: case 3: case 11: case 14: case 15: fixed = 4; break;
        case 6: case 7: case 10: case 16: case 17: case 18: case 19: fixed = 1; break;
        case 20: case 24: fixed = 2; break;
        default: break;
        }
        if (fixed || text) {
            if (seen[type]) return 0;
            seen[type] = 1;
        }
        if (fixed && size != fixed) return 0;
        if (type == 1) {
            if (!discovery_mac(value)) return 0;
            mac = 1;
        } else if (type == 17 && value[0] != 2) return 0;
        if (text) {
            unsigned text_length = size;
            if (text_length && !value[text_length - 1]) text_length--;
            if (!discovery_ascii(value, text_length)) return 0;
            if (text_length && (type == 8 || type == 13)) identity = 1;
        }
        offset += size;
    }
    return mac && identity;
}

int
sql_anywhere_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                          struct UdpPreparedProbe *result)
{
    static const unsigned char request[] =
        "\x1b\x00\x00\x3d\x00\x00\x00\x00\x12" "CONNECTIONLESS_TDS"
        "\x00\x00\x00\x01\x00\x00\x04\x00\x05\x00\x05\x00\x00\x01\x02\x00\x00"
        "\x03\x01\x01\x04\x08\x00\x00\x00\x00\x00\x00\x00\x00\x07\x02\x04\xb1";
    (void)cookie; (void)target;
    memcpy(result->payload, request, sizeof(request) - 1);
    result->length = sizeof(request) - 1;
    return 1;
}

int
sql_anywhere_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned size, offset;
    (void)cookie;
    if (length < 63 || length > 316 || data[0] != 0x1b || data[1] ||
        ((unsigned)data[2] << 8 | data[3]) != length ||
        memcmp(data + 4, "\x00\x00\x00\x00\x12" "CONNECTIONLESS_TDS", 23) ||
        memcmp(data + 27, "\x00\x00\x00\x01\x01\x00\x04\x00\x05\x00\x05\x00", 12)) return 0;
    size = data[39];
    if (size < 2 || length != 61 + size || data[39 + size] ||
        !discovery_ascii(data + 40, size - 1)) return 0;
    offset = 40 + size;
    if (data[offset] != 1 || data[offset + 1] != 2 ||
        !(data[offset + 2] | data[offset + 3])) return 0;
    return !memcmp(data + offset + 4,
        "\x03\x01\x02\x04\x08\x00\x00\x00\x00\x00\x00\x00\x00\x07\x02\x04\xb1", 17);
}

static int
discovery_decimal(const unsigned char *data, unsigned length, unsigned *result)
{
    unsigned i, n = 0;
    if (!length || length > 4) return 0;
    for (i = 0; i < length; i++) {
        if (data[i] < '0' || data[i] > '9') return 0;
        n = n * 10 + data[i] - '0';
    }
    *result = n;
    return 1;
}

static int
discovery_ipv4(const unsigned char *data, unsigned length)
{
    unsigned start = 0, i, fields = 0;
    for (i = 0; i <= length; i++) {
        if (i == length || data[i] == '.') {
            unsigned value;
            if (i - start > 3 || !discovery_decimal(data + start, i - start, &value) || value > 255) return 0;
            fields++; start = i + 1;
        }
    }
    return fields == 4;
}

static int
discovery_hex(unsigned c)
{
    if (c >= '0' && c <= '9') return (int)c - '0';
    if (c >= 'a' && c <= 'f') return (int)c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return (int)c - 'A' + 10;
    return -1;
}

static int
discovery_mac_text(const unsigned char *data, unsigned length)
{
    unsigned char mac[6];
    unsigned i, step;
    if (length != 12 && length != 17) return 0;
    step = length == 12 ? 2 : 3;
    if (step == 3 && data[2] != ':' && data[2] != '-') return 0;
    for (i = 0; i < 6; i++) {
        int a = discovery_hex(data[i * step]), b = discovery_hex(data[i * step + 1]);
        if (a < 0 || b < 0 || (step == 3 && i < 5 && data[i * step + 2] != data[2])) return 0;
        mac[i] = (unsigned char)(a * 16 + b);
    }
    return discovery_mac(mac);
}

int
hifly_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                    struct UdpPreparedProbe *result)
{
    (void)cookie; (void)target;
    memcpy(result->payload, "HF-A11ASSISTHREAD", 17);
    result->length = 17;
    return 1;
}

int
hifly_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned i, first = 0, second = 0;
    (void)cookie;
    if (!length || length > 300) return 0;
    if (data[length - 1] == '\n') {
        length--;
        if (length && data[length - 1] == '\r') length--;
    }
    for (i = 0; i < length; i++) if (data[i] == ',') {
        if (!first) first = i;
        else if (!second) second = i;
        else return 0;
    }
    return first && second == first + 13 && second + 1 < length &&
        discovery_ipv4(data, first) && discovery_mac_text(data + first + 1, 12) &&
        discovery_ascii(data + second + 1, length - second - 1);
}

int
hid_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                  struct UdpPreparedProbe *result)
{
    (void)cookie; (void)target;
    memcpy(result->payload, "discover;013;", 13);
    result->length = 13;
    return 1;
}

int
hid_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    const unsigned char *field[9];
    unsigned size[9], count = 0, start = 0, i, declared, month, day, year, days;
    static const unsigned month_days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    (void)cookie;
    if (!length || length > 999 || data[length - 1] != ';') return 0;
    for (i = 0; i < length; i++) if (data[i] == ';') {
        if (count == 9 || i == start) return 0;
        field[count] = data + start; size[count++] = i - start; start = i + 1;
    }
    if (count != 9 || size[0] != 10 || memcmp(field[0], "discovered", 10) ||
        size[1] != 3 || !discovery_decimal(field[1], 3, &declared) || declared != length ||
        size[2] != 17 || !discovery_mac_text(field[2], 17) ||
        size[3] != 15 || memcmp(field[3], "VertXController", 15) ||
        !discovery_ipv4(field[4], size[4]) || size[5] != 1 || field[5][0] != '2' ||
        !discovery_ascii(field[6], size[6]) || size[7] > 64 || size[8] != 10) return 0;
    for (i = 0; i < size[7]; i++) {
        unsigned c = field[7][i];
        if (c == '.') {
            if (!i || i + 1 == size[7] || field[7][i - 1] == '.') return 0;
        } else if (c < '0' || c > '9') return 0;
    }
    if (field[8][2] != '/' || field[8][5] != '/' ||
        !discovery_decimal(field[8], 2, &month) ||
        !discovery_decimal(field[8] + 3, 2, &day) ||
        !discovery_decimal(field[8] + 6, 4, &year) || !year || !month || month > 12) return 0;
    days = month_days[month - 1];
    if (month == 2 && !(year % 4) && ((year % 100) || !(year % 400))) days++;
    return day && day <= days;
}

int
gardasoft_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                       struct UdpPreparedProbe *result)
{
    (void)cookie; (void)target;
    memcpy(result->payload, "Gardasoft Search", 16);
    result->length = 16;
    return 1;
}

int
gardasoft_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned offset, i;
    (void)cookie;
    if (length == 44 && !memcmp(data, "Gardasoft,PP420,", 16)) offset = 16;
    else if (length == 47 && !memcmp(data, "Gardasoft,TR-RC120,", 19)) offset = 19;
    else return 0;
    for (i = 0; i < 6; i++) if (data[offset + i] < '0' || data[offset + i] > '9') return 0;
    offset += 6;
    if (data[offset] != ',' || !discovery_mac_text(data + offset + 1, 12) || data[offset + 13] != ',') return 0;
    offset += 14;
    for (i = 0; i < 8; i++) if (discovery_hex(data[offset + i]) < 0) return 0;
    return 1;
}

int
gardasoft_version_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                               struct UdpPreparedProbe *result)
{
    (void)cookie; (void)target;
    memcpy(result->payload, "VR\r", 3);
    result->length = 3;
    return 1;
}

int
gardasoft_version_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned start = 0, end = length, i;
    (void)cookie;
    if (!length || length > 256) return 0;
    while (start < end && (data[start] == '\r' || data[start] == '\n')) start++;
    if (end - start >= 3 && !memcmp(data + start, "VR", 2) &&
        (data[start + 2] == '\r' || data[start + 2] == '\n')) {
        start += 3;
        while (start < end && (data[start] == '\r' || data[start] == '\n')) start++;
    }
    while (end > start && (data[end - 1] == '\r' || data[end - 1] == '\n')) end--;
    if (end == start || data[--end] != '>') return 0;
    while (end > start && (data[end - 1] == '\r' || data[end - 1] == '\n')) end--;
    if (end - start != 18 || memcmp(data + start, "PP420 (HW", 9) ||
        memcmp(data + start + 12, ") V", 3)) return 0;
    for (i = 0; i < 3; i++)
        if (data[start + 9 + i] < '0' || data[start + 9 + i] > '9' ||
            data[start + 15 + i] < '0' || data[start + 15 + i] > '9') return 0;
    return 1;
}
