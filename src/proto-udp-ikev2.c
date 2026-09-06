#include "proto-udp-ikev2.h"
#ifdef UDP_EXTENDED_PROBES
#include "proto-udp-runtime.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <string.h>

static unsigned
ikev2_u16(const unsigned char *p)
{
    return (unsigned)p[0] << 8 | p[1];
}

static uint32_t
ikev2_u32(const unsigned char *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static EVP_PKEY *
ikev2_private(uint64_t cookie)
{
    unsigned char private_key[32];
    EVP_PKEY *key;
    if (!udp_probe_derive("ikev2-private", cookie, private_key)) return NULL;
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, sizeof(private_key));
    OPENSSL_cleanse(private_key, sizeof(private_key));
    return key;
}

static int
ikev2_peer_valid(uint64_t cookie, const unsigned char *public_key)
{
    EVP_PKEY *private_key = ikev2_private(cookie);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, public_key, 32);
    EVP_PKEY_CTX *context = private_key ? EVP_PKEY_CTX_new(private_key, NULL) : NULL;
    unsigned char shared[32] = {0};
    size_t length = sizeof(shared);
    unsigned i, nonzero = 0;
    int valid = context && peer && EVP_PKEY_derive_init(context) == 1 &&
        EVP_PKEY_derive_set_peer(context, peer) == 1 &&
        EVP_PKEY_derive(context, shared, &length) == 1 && length == 32;
    for (i = 0; i < sizeof(shared); i++) nonzero |= shared[i];
    OPENSSL_cleanse(shared, sizeof(shared));
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(private_key);
    return valid && nonzero;
}

int
ikev2_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                     struct UdpPreparedProbe *result)
{
    static const unsigned char sa[] =
        "\x22\x00\x00\x30\x00\x00\x00\x2c\x01\x01\x00\x04"
        "\x03\x00\x00\x0c\x01\x00\x00\x0c\x80\x0e\x00\x80"
        "\x03\x00\x00\x08\x02\x00\x00\x05"
        "\x03\x00\x00\x08\x03\x00\x00\x0c"
        "\x00\x00\x00\x08\x04\x00\x00\x1f";
    unsigned char random[32];
    EVP_PKEY *key;
    size_t length = 32;
    unsigned i, nonzero = 0;
    int valid;
    (void)target;
    if (!udp_probe_derive("ikev2-spi", cookie, random)) return 0;
    for (i = 0; i < 8; i++) nonzero |= random[i];
    if (!nonzero) return 0;
    memset(result->payload, 0, 152);
    memcpy(result->payload, random, 8);
    memcpy(result->payload + 16, "\x21\x20\x22\x08", 4);
    result->payload[27] = 152;
    memcpy(result->payload + 28, sa, sizeof(sa) - 1);
    memcpy(result->payload + 76, "\x28\x00\x00\x28\x00\x1f\x00\x00", 8);
    key = ikev2_private(cookie);
    valid = key && EVP_PKEY_get_raw_public_key(key, result->payload + 84, &length) == 1 && length == 32;
    EVP_PKEY_free(key);
    if (!valid || !udp_probe_derive("ikev2-nonce", cookie, result->payload + 120)) return 0;
    result->payload[119] = 36;
    result->length = 152;
    return 1;
}

static int
ikev2_sa(const unsigned char *data, unsigned length)
{
    unsigned offset = 12, seen = 0, count = 0;
    if (length < 12 || data[4] || ikev2_u16(data + 6) != length - 4 ||
        data[8] != 1 || data[9] != 1 || data[10] || data[11] != 4) return 0;
    while (offset < length) {
        unsigned size, type, id;
        if (length - offset < 8) return 0;
        size = ikev2_u16(data + offset + 2);
        type = data[offset + 4];
        id = ikev2_u16(data + offset + 6);
        if (size < 8 || size > length - offset || type < 1 || type > 4 ||
            (seen & (1u << type)) || data[offset] != (offset + size == length ? 0 : 3)) return 0;
        if (type == 1) {
            if (id != 12 || size != 12 || ikev2_u16(data + offset + 8) != 0x800e ||
                ikev2_u16(data + offset + 10) != 128) return 0;
        } else if (size != 8 || id != (type == 2 ? 5 : type == 3 ? 12 : 31)) return 0;
        seen |= 1u << type;
        count++;
        offset += size;
    }
    return count == 4 && seen == 30;
}

int
ikev2_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    unsigned char spi[32];
    const unsigned char *peer = NULL;
    unsigned offset = 28, next, seen = 0, i, nonzero = 0;
    if (length < 28 || length > 4096 || data[17] != 0x20 || data[18] != 34 ||
        (data[19] & 0x28) != 0x20 || ikev2_u32(data + 20) || ikev2_u32(data + 24) != length ||
        !udp_probe_derive("ikev2-spi", cookie, spi) || memcmp(data, spi, 8)) return 0;
    for (i = 8; i < 16; i++) nonzero |= data[i];
    if (!nonzero) return 0;
    next = data[16];
    while (next) {
        unsigned size, bit = 0;
        if (length - offset < 4) return 0;
        size = ikev2_u16(data + offset + 2);
        if (size < 4 || size > length - offset) return 0;
        if (next == 33) {
            bit = 1;
            if (!ikev2_sa(data + offset, size)) return 0;
        } else if (next == 34) {
            bit = 2;
            if (size != 40 || ikev2_u16(data + offset + 4) != 31) return 0;
            peer = data + offset + 8;
        } else if (next == 40) {
            bit = 4;
            if (size < 20 || size > 260) return 0;
        } else if (next == 41) {
            unsigned type;
            if (size != 28 || data[offset + 4] || data[offset + 5]) return 0;
            type = ikev2_u16(data + offset + 6);
            if (type != 16388 && type != 16389) return 0;
        } else if (next == 43) {
            if (size < 5) return 0;
        } else if ((next >= 33 && next <= 48) || (data[offset + 1] & 0x80)) return 0;
        if (bit && (seen & bit)) return 0;
        seen |= bit;
        next = data[offset];
        offset += size;
    }
    return seen == 7 && offset == length && ikev2_peer_valid(cookie, peer);
}
#endif
