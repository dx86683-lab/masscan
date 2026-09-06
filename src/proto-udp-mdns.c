#include "proto-udp-mdns.h"
#include <string.h>

static const unsigned char service_question[] =
    "\x09_services\x07_dns-sd\x04_udp\x05local";

static unsigned
get_u16(const unsigned char *data)
{
    return (unsigned)data[0] << 8 | data[1];
}

/* Expand into canonical wire labels, retaining label boundaries. */
static int
dns_name(const unsigned char *data, unsigned length, unsigned *offset,
         unsigned char name[255], unsigned *name_length)
{
    unsigned cursor = *offset, used = 0, steps = 0, jumped = 0;
    while (cursor < length && steps++ < 128) {
        unsigned size = data[cursor++], i;
        if ((size & 192) == 192) {
            unsigned pointer;
            if (cursor >= length) return 0;
            pointer = ((size & 63) << 8) | data[cursor++];
            if (pointer < 12 || pointer >= cursor - 2) return 0;
            if (!jumped) *offset = cursor;
            jumped = 1;
            cursor = pointer;
            continue;
        }
        if (size > 63 || size > length - cursor || used + size + 1 > 255) return 0;
        name[used++] = (unsigned char)size;
        for (i = 0; i < size; i++) {
            unsigned ch = data[cursor++];
            name[used++] = (unsigned char)(ch >= 'A' && ch <= 'Z' ? ch + 32 : ch);
        }
        if (!size) {
            if (!jumped) *offset = cursor;
            *name_length = used;
            return 1;
        }
    }
    return 0;
}

static int
is_service_type(const unsigned char *name, unsigned length)
{
    unsigned n, i, letter = 0;
    if (length < 14 || name[0] < 2 || name[0] > 16 || name[1] != '_') return 0;
    n = name[0];
    if (length != n + 13) return 0;
    for (i = 2; i <= n; i++) {
        unsigned ch = name[i];
        if (ch >= 'a' && ch <= 'z') letter = 1;
        else if (!(ch >= '0' && ch <= '9') && ch != '-') return 0;
    }
    if (!letter || name[2] == '-' || name[n] == '-') return 0;
    return (!memcmp(name + n + 1, "\x04_tcp\x05local", 12) ||
            !memcmp(name + n + 1, "\x04_udp\x05local", 12));
}

int
mdns_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                   struct UdpPreparedProbe *result)
{
    if (target && target->source_port == 5353) return 0;
    memset(result->payload, 0, 12);
    result->payload[0] = (unsigned char)(cookie >> 8);
    result->payload[1] = (unsigned char)cookie;
    result->payload[5] = 1;
    memcpy(result->payload + 12, service_question, sizeof(service_question));
    memcpy(result->payload + 42, "\x00\x0c\x00\x01", 4);
    result->length = 46;
    return 1;
}

int
mdns_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned offset = 12, name_length, count, answers, i, found = 0;
    unsigned char name[255], value[255];
    if (length < 12 || get_u16(data) != (cookie & 65535) ||
        (get_u16(data + 2) & 0xfbff) != 0x8000 || get_u16(data + 4) != 1) return 0;
    answers = get_u16(data + 6);
    count = answers + get_u16(data + 8) + get_u16(data + 10);
    if (!answers || count > 512 ||
        !dns_name(data, length, &offset, name, &name_length) ||
        name_length != sizeof(service_question) || memcmp(name, service_question, name_length) ||
        length - offset < 4 || get_u16(data + offset) != 12 ||
        get_u16(data + offset + 2) != 1) return 0;
    offset += 4;
    for (i = 0; i < count; i++) {
        unsigned type, size, end, cursor, value_length;
        if (!dns_name(data, length, &offset, name, &name_length) || length - offset < 10) return 0;
        type = get_u16(data + offset);
        if (get_u16(data + offset + 2) != 1) return 0;
        size = get_u16(data + offset + 8);
        offset += 10;
        if (size > length - offset) return 0;
        end = offset + size;
        cursor = offset;
        if (type == 12 || type == 5 || type == 2 || type == 33) {
            if (type == 33) {
                if (size < 7) return 0;
                cursor += 6;
            }
            if (!dns_name(data, length, &cursor, value, &value_length) || cursor != end) return 0;
            if (type == 12 && i < answers && name_length == sizeof(service_question) &&
                !memcmp(name, service_question, name_length) && is_service_type(value, value_length)) found = 1;
        } else if (type == 1) {
            if (size != 4) return 0;
        } else if (type == 28) {
            if (size != 16) return 0;
        } else if (type == 16) {
            if (!size) return 0;
            while (cursor < end) {
                unsigned text_length = data[cursor++];
                if (text_length > end - cursor) return 0;
                cursor += text_length;
            }
        }
        offset = end;
    }
    return found && offset == length;
}
