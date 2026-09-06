#include "proto-udp-text-discovery.h"
#include "proto-udp-discovery-fields.h"
#include "proto-udp-runtime.h"
#include <string.h>
#include <stdio.h>

int
serialnumberd_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                           struct UdpPreparedProbe *result)
{
    static const char query[] = "SNQUERY: 127.0.0.1:AAAAAA:xsvr";
    (void)cookie; (void)target;
    memcpy(result->payload, query, sizeof(query) - 1);
    result->length = sizeof(query) - 1;
    return 1;
}

int
serialnumberd_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    const unsigned char *field[8];
    unsigned sizes[8], count = 0, start = 0, i, f;
    (void)cookie;
    if (!length || length > 1024 || data[length - 1]) return 0;
    for (i = 0; i < length; i++) {
        if (!data[i] && i != length - 1) return 0;
        if (data[i] == ':' || i == length - 1) {
            if (count == 8 || i == start) return 0;
            field[count] = data + start; sizes[count++] = i - start; start = i + 1;
        }
    }
    if (count != 8 || sizes[0] != 7 || memcmp(field[0], "SNRESPS", 7) ||
        sizes[3] != 4 || memcmp(field[3], "xsvr", 4) || sizes[1] > 255 ||
        sizes[1] != sizes[7] || memcmp(field[1], field[7], sizes[1])) return 0;
    for (i = 0; i < sizes[1]; i++) {
        unsigned c = field[1][i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) return 0;
    }
    for (f = 2; f <= 6; f++) {
        unsigned lower = f == 5;
        if (f == 3) continue;
        if (sizes[f] != (lower ? 10u : 42u) || memcmp(field[f], "0x", 2)) return 0;
        for (i = 2; i < sizes[f]; i++) {
            unsigned c = field[f][i];
            if (!((c >= '0' && c <= '9') ||
                  (c >= (lower ? 'a' : 'A') && c <= (lower ? 'f' : 'F')))) return 0;
        }
    }
    return 1;
}

#ifdef UDP_EXTENDED_PROBES
#include <expat.h>

struct SadpXml {
    XML_Parser parser;
    unsigned depth, elements, namespaces, failed, seen, field, used, identity;
    unsigned char text[512];
};

static void
sadp_fail(struct SadpXml *state)
{
    state->failed = 1;
    XML_StopParser(state->parser, XML_FALSE);
}

static void XMLCALL
sadp_start(void *context, const XML_Char *name, const XML_Char **attributes)
{
    static const char *fields[] = {"MAC", "DeviceType", "DeviceDescription", "Types",
        "IPv4Address", "IPv4SubnetMask", "IPv4Gateway", "CommandPort", "HttpPort", "Uuid",
        "SoftwareVersion", "DSPVersion"};
    struct SadpXml *s = context;
    unsigned i, count = 0;
    if (s->failed) return;
    while (attributes[count * 2]) if (++count > 16) { sadp_fail(s); return; }
    if (++s->depth > 8 || ++s->elements > 128 || s->field) { sadp_fail(s); return; }
    if (s->depth == 1 && strcmp(name, "ProbeMatch")) { sadp_fail(s); return; }
    if (s->depth != 2) return;
    for (i = 0; i < sizeof(fields) / sizeof(*fields); i++) if (!strcmp(name, fields[i])) {
        if (s->seen & (1u << i)) { sadp_fail(s); return; }
        s->seen |= 1u << i; s->field = i + 1; s->used = 0;
        break;
    }
}

static void XMLCALL
sadp_end(void *context, const XML_Char *name)
{
    struct SadpXml *s = context;
    unsigned i, valid = 1;
    (void)name;
    if (s->failed) return;
    if (s->depth == 2 && s->field) {
        if (s->field == 1) valid = s->used == 17 && udp_discovery_mac_text(s->text, s->used);
        else if (s->field == 2 || s->field == 3) {
            unsigned nonspace = 0;
            for (i = 0; i < s->used; i++) {
                if (s->text[i] < 32) valid = 0;
                nonspace |= s->text[i] > 32;
            }
            valid &= nonspace != 0;
            if (valid) s->identity = 1;
        } else if (s->field == 4) valid = s->used == 7 && !memcmp(s->text, "inquiry", 7);
        else if (s->field >= 5 && s->field <= 7) valid = udp_discovery_ipv4(s->text, s->used);
        else if (s->field == 8 || s->field == 9) {
            unsigned port = 0;
            valid = s->used > 0 && s->used <= 5;
            for (i = 0; valid && i < s->used; i++) {
                if (s->text[i] < '0' || s->text[i] > '9') valid = 0;
                else port = port * 10 + s->text[i] - '0';
            }
            valid &= port > 0 && port <= 65535;
        }
        if (!valid) { sadp_fail(s); return; }
        s->field = 0;
    }
    s->depth--;
}

static void XMLCALL
sadp_text(void *context, const XML_Char *text, int length)
{
    struct SadpXml *s = context;
    int i;
    if (s->failed) return;
    if (!s->field) {
        if (s->depth <= 1) for (i = 0; i < length; i++)
            if (text[i] != ' ' && text[i] != '\r' && text[i] != '\n' && text[i] != '\t') { sadp_fail(s); return; }
        return;
    }
    if (length < 0 || (unsigned)length > sizeof(s->text) - s->used) { sadp_fail(s); return; }
    memcpy(s->text + s->used, text, (unsigned)length); s->used += (unsigned)length;
}

static void XMLCALL
sadp_doctype(void *context, const XML_Char *name, const XML_Char *system_id,
             const XML_Char *public_id, int internal)
{
    (void)name; (void)system_id; (void)public_id; (void)internal;
    sadp_fail(context);
}

static int XMLCALL
sadp_external(XML_Parser parser, const XML_Char *context, const XML_Char *base,
              const XML_Char *system_id, const XML_Char *public_id)
{
    (void)parser; (void)context; (void)base; (void)system_id; (void)public_id;
    return XML_STATUS_ERROR;
}

static void XMLCALL
sadp_namespace(void *context, const XML_Char *prefix, const XML_Char *uri)
{
    struct SadpXml *s = context;
    (void)prefix; (void)uri;
    if (!s->failed && ++s->namespaces > 32) sadp_fail(s);
}

int
hikvision_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                        struct UdpPreparedProbe *result)
{
    unsigned char bytes[32];
    char uuid[37];
    static const char hex[] = "0123456789abcdef";
    unsigned i, used = 0;
    int length;
    if (!udp_probe_derive_target("sadp-inquiry", cookie, 37020, target, bytes)) return 0;
    bytes[6] = (bytes[6] & 15) | 0x40; bytes[8] = (bytes[8] & 63) | 0x80;
    for (i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) uuid[used++] = '-';
        uuid[used++] = hex[bytes[i] >> 4]; uuid[used++] = hex[bytes[i] & 15];
    }
    uuid[used] = 0;
    length = snprintf((char *)result->payload, sizeof(result->payload),
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><Probe><Uuid>%s</Uuid><Types>inquiry</Types></Probe>", uuid);
    if (length < 0 || (unsigned)length >= sizeof(result->payload)) return 0;
    result->length = (unsigned)length;
    return 1;
}

static void XMLCALL
sadp_declaration(void *context, const XML_Char *version, const XML_Char *encoding, int standalone)
{
    struct SadpXml *s = context;
    unsigned i;
    (void)standalone;
    if (s->failed) return;
    if (!version || strcmp(version, "1.0")) { sadp_fail(s); return; }
    if (!encoding) return;
    if (strlen(encoding) != 5) { sadp_fail(s); return; }
    for (i = 0; i < 5; i++)
        if (((unsigned char)encoding[i] | 32) != (unsigned char)"utf-8"[i]) { sadp_fail(s); return; }
}

int
hikvision_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    struct SadpXml state = {0};
    int parsed, valid;
    (void)cookie;
    if (!length || length > 8192) return 0;
    state.parser = XML_ParserCreateNS("UTF-8", '\x1f');
    if (!state.parser) return 0;
    XML_SetUserData(state.parser, &state);
    XML_SetElementHandler(state.parser, sadp_start, sadp_end);
    XML_SetCharacterDataHandler(state.parser, sadp_text);
    XML_SetStartDoctypeDeclHandler(state.parser, sadp_doctype);
    XML_SetExternalEntityRefHandler(state.parser, sadp_external);
    XML_SetStartNamespaceDeclHandler(state.parser, sadp_namespace);
    XML_SetXmlDeclHandler(state.parser, sadp_declaration);
    XML_SetParamEntityParsing(state.parser, XML_PARAM_ENTITY_PARSING_NEVER);
    parsed = XML_Parse(state.parser, (const char *)data, (int)length, XML_TRUE);
    valid = parsed == XML_STATUS_OK && !state.failed && !state.depth && (state.seen & 1) && state.identity;
    XML_ParserFree(state.parser);
    return valid;
}
#endif
