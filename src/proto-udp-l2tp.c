#include "proto-udp-l2tp.h"
#include <string.h>

static unsigned
l2tp_u16(const unsigned char *p)
{
    return (unsigned)p[0] << 8 | p[1];
}

static unsigned
l2tp_tunnel_id(uint64_t cookie)
{
    unsigned id = (unsigned)cookie & 65535;
    return id ? id : 1;
}

int
l2tp_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                    struct UdpPreparedProbe *result)
{
    static const unsigned char request[] =
        "\xc8\x02\x00\x3b\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x80\x08\x00\x00\x00\x00\x00\x01"
        "\x80\x08\x00\x00\x00\x02\x01\x00"
        "\x80\x0d\x00\x00\x00\x07scanner"
        "\x80\x0a\x00\x00\x00\x03\x00\x00\x00\x00"
        "\x80\x08\x00\x00\x00\x09\x00\x00";
    unsigned id = l2tp_tunnel_id(cookie);
    (void)target;
    memcpy(result->payload, request, sizeof(request) - 1);
    result->payload[57] = (unsigned char)(id >> 8);
    result->payload[58] = (unsigned char)id;
    result->length = sizeof(request) - 1;
    return 1;
}

int
l2tp_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned offset = 12, seen = 0;
    const unsigned required = (1u << 0) | (1u << 2) | (1u << 3) | (1u << 7) | (1u << 9);
    if (length < 20 || length > 4096 ||
        (l2tp_u16(data) & 0xcb0f) != 0xc802 || l2tp_u16(data + 2) != length ||
        l2tp_u16(data + 4) != l2tp_tunnel_id(cookie) || l2tp_u16(data + 6) ||
        l2tp_u16(data + 8) || l2tp_u16(data + 10) != 1) return 0;
    while (offset < length) {
        unsigned flags, size, vendor, type, mandatory;
        const unsigned char *value;
        if (length - offset < 6) return 0;
        flags = l2tp_u16(data + offset);
        size = flags & 1023;
        vendor = l2tp_u16(data + offset + 2);
        type = l2tp_u16(data + offset + 4);
        mandatory = flags & 0x8000;
        if (size < 6 || size > length - offset) return 0;
        if (offset == 12 && (vendor || type || flags != 0x8008)) return 0;
        value = data + offset + 6;
        offset += size;
        if (vendor || (flags & 0x3c00) || type > 13 || type == 1 || type == 5 || type == 12) {
            if (mandatory) return 0;
            continue;
        }
        if (flags & 0x4000) return 0;
        if (seen & (1u << type)) return 0;
        seen |= 1u << type;
        if ((type == 6 || type == 8) ? mandatory != 0 : mandatory == 0) return 0;
        switch (type) {
        case 0: if (size != 8 || l2tp_u16(value) != 2) return 0; break;
        case 2: if (size != 8 || l2tp_u16(value) != 0x0100) return 0; break;
        case 3: case 4: if (size != 10) return 0; break;
        case 6: if (size != 8) return 0; break;
        case 7: case 11: if (size < 7) return 0; break;
        case 8: break;
        case 9: case 10: if (size != 8 || !l2tp_u16(value)) return 0; break;
        /* No challenge was sent, so a response cannot be verified. */
        case 13: return 0;
        default: return 0;
        }
    }
    return (seen & required) == required;
}
