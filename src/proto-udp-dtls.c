#include "proto-udp-dtls.h"
#ifdef UDP_EXTENDED_PROBES
#include "proto-udp-runtime.h"
#include <string.h>
#include <time.h>

static unsigned
dtls_u16(const unsigned char *p)
{
    return (unsigned)p[0] << 8 | p[1];
}

static unsigned
dtls_u24(const unsigned char *p)
{
    return (unsigned)p[0] << 16 | (unsigned)p[1] << 8 | p[2];
}

int
dtls_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                   struct UdpPreparedProbe *result)
{
    unsigned char random[32];
    time_t now = time(NULL);
    unsigned i;
    (void)target;
    if (now == (time_t)-1 || !udp_probe_derive("dtls-random", cookie, random)) return 0;
    memset(result->payload, 0, 67);
    memcpy(result->payload, "\x16\xfe\xfd", 3);
    result->payload[12] = 54;
    result->payload[13] = 1;
    result->payload[16] = 42;
    result->payload[24] = 42;
    result->payload[25] = 254;
    result->payload[26] = 253;
    for (i = 0; i < 4; i++) result->payload[27 + i] = (unsigned char)((uint32_t)now >> (24 - i * 8));
    memcpy(result->payload + 31, random, 28);
    memcpy(result->payload + 59, "\x00\x00\x00\x02\x00\x2f\x01\x00", 8);
    result->length = 67;
    return 1;
}

static int
dtls_server_hello(const unsigned char *data, unsigned length)
{
    unsigned session, offset;
    if (length < 38 || dtls_u16(data) != 0xfefd) return 0;
    session = data[34];
    if (session > 32 || session > length - 38) return 0;
    offset = 35 + session;
    if (dtls_u16(data + offset) != 0x002f || data[offset + 2] != 0) return 0;
    offset += 3;
    return offset == length || (length - offset == 2 && dtls_u16(data + offset) == 0);
}

static int
dtls_certificates(const unsigned char *data, unsigned length)
{
    unsigned offset = 3, count = 0;
    if (length < 3 || dtls_u24(data) != length - 3) return 0;
    while (offset < length) {
        unsigned size;
        if (length - offset < 3) return 0;
        size = dtls_u24(data + offset);
        offset += 3;
        if (!size || size > length - offset) return 0;
        offset += size;
        count++;
    }
    return count != 0;
}

int
dtls_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned offset = 0, record = 0, message = 0, hello = 0, hvr = 0, certificate = 0, done = 0;
    (void)cookie;
    while (offset < length) {
        unsigned end, size, cursor, i;
        const unsigned char *header = data + offset;
        if (length - offset < 13 || header[0] != 22 ||
            (dtls_u16(header + 1) != 0xfeff && dtls_u16(header + 1) != 0xfefd) ||
            dtls_u16(header + 3) != 0 || hvr || done) return 0;
        for (i = 5; i < 10; i++) if (header[i]) return 0;
        if (record > 255 || header[10] != record++) return 0;
        size = dtls_u16(header + 11);
        offset += 13;
        if (!size || size > length - offset) return 0;
        end = offset + size;
        cursor = offset;
        while (cursor < end) {
            unsigned type;
            const unsigned char *body;
            if (end - cursor < 12 || hvr || done) return 0;
            type = data[cursor];
            size = dtls_u24(data + cursor + 1);
            if (dtls_u16(data + cursor + 4) != message++ || dtls_u24(data + cursor + 6) ||
                dtls_u24(data + cursor + 9) != size) return 0;
            cursor += 12;
            if (size > end - cursor) return 0;
            body = data + cursor;
            if (type == 3) {
                if (message != 1 || size < 4 ||
                    (dtls_u16(body) != 0xfeff && dtls_u16(body) != 0xfefd) ||
                    body[2] == 0 || size != 3u + body[2]) return 0;
                hvr = 1;
            } else if (type == 2) {
                if (message != 1 || !dtls_server_hello(body, size)) return 0;
                hello = 1;
            } else if (type == 11) {
                if (!hello || certificate || !dtls_certificates(body, size)) return 0;
                certificate = 1;
            } else if (type == 14) {
                if (!hello || !certificate || size) return 0;
                done = 1;
            } else return 0;
            cursor += size;
        }
        offset = end;
    }
    return hello || hvr;
}
#endif
