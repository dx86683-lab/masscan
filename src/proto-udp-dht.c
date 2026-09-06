#include "proto-udp-dht.h"
#ifdef UDP_EXTENDED_PROBES
#include "proto-udp-runtime.h"
#include <string.h>

enum BKind { B_STRING, B_INTEGER, B_LIST, B_DICT };
struct BValue {
    enum BKind kind;
    const unsigned char *text;
    unsigned length, child, next;
    int64_t number;
};
struct BParser {
    const unsigned char *data;
    unsigned length, offset, used;
    struct BValue values[64];
};

static int
b_parse(struct BParser *p, unsigned depth)
{
    struct BValue *v;
    unsigned kind, start, index;
    uint64_t number = 0;
    if (depth > 8 || p->used == 64 || p->offset == p->length) return 0;
    index = p->used++;
    v = p->values + index;
    kind = p->data[p->offset++];
    if (kind >= '0' && kind <= '9') {
        number = kind - '0';
        while (p->offset < p->length && p->data[p->offset] != ':') {
            unsigned digit = p->data[p->offset++] - '0';
            if (kind == '0' || digit > 9 || number > 4096) return 0;
            number = number * 10 + digit;
        }
        if (p->offset == p->length || ++p->offset > p->length || number > p->length - p->offset) return 0;
        v->kind = B_STRING;
        v->text = p->data + p->offset;
        v->length = (unsigned)number;
        p->offset += (unsigned)number;
    } else if (kind == 'i') {
        unsigned negative = 0;
        uint64_t limit;
        if (p->offset < p->length && p->data[p->offset] == '-') { negative = 1; p->offset++; }
        start = p->offset;
        limit = (uint64_t)INT64_MAX + negative;
        while (p->offset < p->length && p->data[p->offset] != 'e') {
            unsigned digit = p->data[p->offset++] - '0';
            if (digit > 9 || number > limit / 10 ||
                (number == limit / 10 && digit > limit % 10)) return 0;
            number = number * 10 + digit;
        }
        if (p->offset == p->length || p->offset == start ||
            (p->offset - start > 1 && p->data[start] == '0') || (negative && !number)) return 0;
        p->offset++;
        v->kind = B_INTEGER;
        v->number = negative ? -(int64_t)(number - 1) - 1 : (int64_t)number;
    } else if (kind == 'l' || kind == 'd') {
        const struct BValue *previous = NULL;
        v->kind = kind == 'l' ? B_LIST : B_DICT;
        v->child = p->used;
        while (p->offset < p->length && p->data[p->offset] != 'e') {
            unsigned child = p->used;
            if (!b_parse(p, depth + 1)) return 0;
            if (kind == 'd') {
                const struct BValue *key = p->values + child;
                if (key->kind != B_STRING) return 0;
                if (previous) {
                    unsigned common = previous->length < key->length ? previous->length : key->length;
                    int cmp = memcmp(previous->text, key->text, common);
                    if (cmp > 0 || (!cmp && previous->length >= key->length)) return 0;
                }
                previous = key;
                if (!b_parse(p, depth + 1)) return 0;
            }
        }
        if (p->offset == p->length) return 0;
        p->offset++;
    } else return 0;
    v->next = p->used;
    return 1;
}

static const struct BValue *
b_get(const struct BParser *p, const struct BValue *dictionary, const char *name)
{
    unsigned i;
    if (!dictionary || dictionary->kind != B_DICT) return NULL;
    for (i = dictionary->child; i < dictionary->next; ) {
        const struct BValue *key = p->values + i;
        const struct BValue *value = p->values + key->next;
        if (key->length == strlen(name) && !memcmp(key->text, name, key->length)) return value;
        i = value->next;
    }
    return NULL;
}

int
dht_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                  struct UdpPreparedProbe *result)
{
    unsigned char node[32];
    unsigned offset = 0, i;
    static const char prefix[] = "d1:ad2:id20:";
    static const char middle[] = "e1:q4:ping1:t4:";
    static const char suffix[] = "1:y1:qe";
    (void)target;
    if (!udp_probe_derive("dht-node", 0, node)) return 0;
    memcpy(result->payload, prefix, sizeof(prefix) - 1);
    offset += sizeof(prefix) - 1;
    memcpy(result->payload + offset, node, 20);
    offset += 20;
    memcpy(result->payload + offset, middle, sizeof(middle) - 1);
    offset += sizeof(middle) - 1;
    for (i = 0; i < 4; i++) result->payload[offset++] = (unsigned char)(cookie >> (24 - i * 8));
    memcpy(result->payload + offset, suffix, sizeof(suffix) - 1);
    result->length = offset + sizeof(suffix) - 1;
    return 1;
}

int
dht_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    struct BParser p = {0};
    const struct BValue *t, *y, *value;
    unsigned i;
    if (!length || length > 4096) return 0;
    p.data = data;
    p.length = length;
    if (!b_parse(&p, 0) || p.offset != length) return 0;
    t = b_get(&p, p.values, "t");
    y = b_get(&p, p.values, "y");
    if (!t || t->kind != B_STRING || t->length != 4 ||
        !y || y->kind != B_STRING || y->length != 1) return 0;
    for (i = 0; i < 4; i++) if (t->text[i] != (unsigned char)(cookie >> (24 - i * 8))) return 0;
    if (y->text[0] == 'r') {
        if (b_get(&p, p.values, "e") || b_get(&p, p.values, "q")) return 0;
        value = b_get(&p, b_get(&p, p.values, "r"), "id");
        return value && value->kind == B_STRING && value->length == 20;
    }
    if (y->text[0] == 'e') {
        const struct BValue *code, *message;
        if (b_get(&p, p.values, "r") || b_get(&p, p.values, "q")) return 0;
        value = b_get(&p, p.values, "e");
        if (!value || value->kind != B_LIST || value->child == value->next) return 0;
        code = p.values + value->child;
        if (code->next >= value->next) return 0;
        message = p.values + code->next;
        return code->kind == B_INTEGER && code->number >= 201 && code->number <= 204 &&
            message->kind == B_STRING && message->next == value->next;
    }
    return 0;
}
#endif
