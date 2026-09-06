#include "proto-udp-sqlr.h"
#include <string.h>

struct SqlrText {
    const unsigned char *data;
    unsigned length;
};

static int
sqlr_field(struct SqlrText *input, struct SqlrText *field)
{
    unsigned i;
    for (i = 0; i < input->length; i++) {
        if (!input->data[i]) return 0;
        if (input->data[i] != ';') continue;
        field->data = input->data;
        field->length = i;
        input->data += i + 1;
        input->length -= i + 1;
        return 1;
    }
    return 0;
}

static int
sqlr_equal(struct SqlrText text, const char *literal)
{
    unsigned i;
    if (text.length != strlen(literal)) return 0;
    for (i = 0; i < text.length; i++) {
        unsigned ch = text.data[i];
        if (ch >= 'A' && ch <= 'Z') ch += 32;
        if (ch != (unsigned char)literal[i]) return 0;
    }
    return 1;
}

static int
sqlr_decimal(struct SqlrText text, uint32_t limit, int nonzero)
{
    uint32_t value = 0;
    unsigned i;
    if (!text.length) return 0;
    for (i = 0; i < text.length; i++) {
        unsigned digit = text.data[i] - '0';
        if (digit > 9 || value > limit / 10 ||
            (value == limit / 10 && digit > limit % 10)) return 0;
        value = value * 10 + digit;
    }
    return !nonzero || value != 0;
}

static int
sqlr_via(struct SqlrText text)
{
    unsigned offset = 0, start;
    struct SqlrText number;
    while (offset < text.length && text.data[offset] != ',') offset++;
    if (offset > 15 || offset == text.length) return 0;
    while (offset < text.length) {
        offset++;
        start = offset;
        while (offset < text.length && text.data[offset] != ':' && text.data[offset] != ',') offset++;
        if (offset == text.length || offset == start || text.data[offset++] != ':') return 0;
        number.data = text.data + offset;
        start = offset;
        while (offset < text.length && text.data[offset] != ',') offset++;
        number.length = offset - start;
        if (!sqlr_decimal(number, UINT32_MAX, 0)) return 0;
    }
    return 1;
}

int
sqlr_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                   struct UdpPreparedProbe *result)
{
    (void)cookie;
    (void)target;
    result->payload[0] = 3;
    result->length = 1;
    return 1;
}

int
sqlr_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    struct SqlrText input, key, value;
    unsigned instances = 0;
    (void)cookie;
    if (length < 3 || data[0] != 5 ||
        ((unsigned)data[2] << 8 | data[1]) != length - 3) return 0;
    input.data = data + 3;
    input.length = length - 3;
    while (input.length) {
        static const char *required[] = {"servername", "instancename", "isclustered", "version"};
        static const char *transports[] = {"np", "tcp", "via", "rpc", "spx", "adsp", "bv"};
        unsigned before = input.length, seen = 0, i;
        for (i = 0; i < 4; i++) {
            unsigned j;
            if (!sqlr_field(&input, &key) || !sqlr_equal(key, required[i]) ||
                !sqlr_field(&input, &value)) return 0;
            if (i < 2 && value.length > 255) return 0;
            if (i == 2 && !sqlr_equal(value, "yes") && !sqlr_equal(value, "no")) return 0;
            if (i != 3) continue;
            if (!value.length || value.length > 16) return 0;
            for (j = 0; j < value.length; j++)
                if (value.data[j] != '.' && (value.data[j] < '0' || value.data[j] > '9')) return 0;
        }
        while (input.length && input.data[0] != ';') {
            unsigned count, j;
            if (!sqlr_field(&input, &key)) return 0;
            for (i = 0; i < 7; i++)
                if (sqlr_equal(key, transports[i])) break;
            if (i == 7 || (seen & (1u << i))) return 0;
            seen |= 1u << i;
            count = i == 6 ? 5 : 1;
            for (j = 0; j < count; j++) {
                if (!sqlr_field(&input, &value)) return 0;
                if (i == 1 && !sqlr_decimal(value, 65535, 1)) return 0;
                if (i == 2 && !sqlr_via(value)) return 0;
                if (i == 4 && value.length > 1024) return 0;
            }
        }
        if (!input.length || input.data[0] != ';') return 0;
        input.data++;
        input.length--;
        if (before - input.length > 1024) return 0;
        instances++;
    }
    return instances != 0;
}
