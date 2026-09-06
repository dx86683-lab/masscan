#include "proto-udp-snmpv3.h"
#include <string.h>

struct BerSpan {
    const unsigned char *data;
    unsigned length;
};

static int
ber_take(struct BerSpan *input, unsigned tag, struct BerSpan *value)
{
    unsigned offset = 2, size, count, i;
    if (input->length < 2 || input->data[0] != tag) return 0;
    size = input->data[1];
    if (size & 128) {
        count = size & 127;
        if (count == 0 || count > 4 || count > input->length - offset) return 0;
        size = 0;
        for (i = 0; i < count; i++) size = (size << 8) | input->data[offset++];
    }
    if (size > input->length - offset) return 0;
    value->data = input->data + offset;
    value->length = size;
    input->data += offset + size;
    input->length -= offset + size;
    return 1;
}

static int
ber_uint(struct BerSpan *input, unsigned tag, uint32_t limit, uint32_t *value)
{
    struct BerSpan bytes;
    uint64_t number = 0;
    unsigned i;
    if (!ber_take(input, tag, &bytes) || bytes.length == 0 || bytes.length > 5 ||
        (bytes.data[0] & 128)) return 0;
    if (bytes.length > 1 && bytes.data[0] == 0 && (bytes.data[1] & 128) == 0) return 0;
    for (i = 0; i < bytes.length; i++) number = (number << 8) | bytes.data[i];
    if (number > limit) return 0;
    *value = (uint32_t)number;
    return 1;
}

static unsigned
ber_put_uint(unsigned char *data, uint32_t value)
{
    unsigned count = 1, i;
    while (count < 4 && (value >> (count * 8))) count++;
    if ((value >> ((count - 1) * 8)) & 128) count++;
    data[0] = 2;
    data[1] = (unsigned char)count;
    for (i = 0; i < count; i++) data[2 + i] = (unsigned char)(value >> ((count - i - 1) * 8));
    return count + 2;
}

int
snmpv3_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                     struct UdpPreparedProbe *result)
{
    unsigned offset = 7, global = 5, scoped, pdu;
    unsigned char *data = result->payload;
    uint32_t id = (uint32_t)cookie & 0x7fffffff;
    (void)target;
    memcpy(data, "\x30\x00\x02\x01\x03\x30\x00", 7);
    offset += ber_put_uint(data + offset, id);
    memcpy(data + offset, "\x02\x02\x05\xdc\x04\x01\x04\x02\x01\x03", 10);
    offset += 10;
    data[global + 1] = (unsigned char)(offset - global - 2);
    memcpy(data + offset, "\x04\x10\x30\x0e\x04\x00\x02\x01\x00\x02\x01\x00\x04\x00\x04\x00\x04\x00", 18);
    offset += 18;
    scoped = offset;
    memcpy(data + offset, "\x30\x00\x04\x00\x04\x00\xa0\x00", 8);
    pdu = offset + 6;
    offset += 8;
    offset += ber_put_uint(data + offset, id);
    memcpy(data + offset, "\x02\x01\x00\x02\x01\x00\x30\x00", 8);
    offset += 8;
    data[pdu + 1] = (unsigned char)(offset - pdu - 2);
    data[scoped + 1] = (unsigned char)(offset - scoped - 2);
    data[1] = (unsigned char)(offset - 2);
    result->length = offset;
    return 1;
}

int
snmpv3_probe_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    struct BerSpan packet = {response, length}, root, global, security, parameters;
    struct BerSpan engine, value, scoped, pdu, bindings, binding;
    uint32_t number, id = (uint32_t)cookie & 0x7fffffff;
    unsigned i, nonzero = 0, nonff = 0;
    if (!ber_take(&packet, 0x30, &root) || packet.length ||
        !ber_uint(&root, 2, 3, &number) || number != 3 ||
        !ber_take(&root, 0x30, &global)) return 0;
    if (!ber_uint(&global, 2, 0x7fffffff, &number) || number != id ||
        !ber_uint(&global, 2, 0x7fffffff, &number) || number < 484 ||
        !ber_take(&global, 4, &value) || value.length != 1 || value.data[0] != 0 ||
        !ber_uint(&global, 2, 3, &number) || number != 3 || global.length) return 0;
    if (!ber_take(&root, 4, &security) || !ber_take(&security, 0x30, &parameters) ||
        security.length || !ber_take(&parameters, 4, &engine) ||
        engine.length < 5 || engine.length > 32) return 0;
    for (i = 0; i < engine.length; i++) {
        nonzero |= engine.data[i];
        nonff |= engine.data[i] ^ 255;
    }
    if (!nonzero || !nonff ||
        !ber_uint(&parameters, 2, 0x7fffffff, &number) ||
        !ber_uint(&parameters, 2, 0x7fffffff, &number)) return 0;
    for (i = 0; i < 3; i++)
        if (!ber_take(&parameters, 4, &value) || value.length) return 0;
    if (parameters.length || !ber_take(&root, 0x30, &scoped) || root.length ||
        !ber_take(&scoped, 4, &value)) return 0;
    if (value.length && (value.length != engine.length || memcmp(value.data, engine.data, value.length)))
        return 0;
    if (!ber_take(&scoped, 4, &value) || value.length ||
        !ber_take(&scoped, 0xa8, &pdu) || scoped.length ||
        !ber_uint(&pdu, 2, 0x7fffffff, &number) || (number != 0 && number != id) ||
        !ber_uint(&pdu, 2, 0, &number) || !ber_uint(&pdu, 2, 0, &number) ||
        !ber_take(&pdu, 0x30, &bindings) || pdu.length ||
        !ber_take(&bindings, 0x30, &binding) || bindings.length ||
        !ber_take(&binding, 6, &value) || value.length != 10 ||
        memcmp(value.data, "\x2b\x06\x01\x06\x03\x0f\x01\x01\x04\x00", 10) ||
        !ber_uint(&binding, 0x41, UINT32_MAX, &number) || binding.length) return 0;
    return 1;
}
