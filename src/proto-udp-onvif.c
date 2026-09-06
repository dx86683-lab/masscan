#include "proto-udp-onvif.h"
#ifdef UDP_EXTENDED_PROBES
#include "proto-udp-runtime.h"
#include "massip-parse.h"
#include <expat.h>
#include <stdio.h>
#include <string.h>

#define SOAP_URI "http://www.w3.org/2003/05/soap-envelope"
#define ADDR_URI "http://schemas.xmlsoap.org/ws/2004/08/addressing"
#define DISC_URI "http://schemas.xmlsoap.org/ws/2005/04/discovery"
#define DEVICE_URI "http://www.onvif.org/ver10/device/wsdl"
#define XNAME(uri, local) uri "\x1f" local

enum OnvifElement {
    O_UNKNOWN, O_ENVELOPE, O_HEADER, O_BODY, O_ACTION, O_ID, O_RELATES,
    O_TO, O_SEQUENCE, O_MATCHES, O_MATCH, O_ENDPOINT, O_ADDRESS,
    O_TYPES, O_SCOPES, O_XADDRS, O_METADATA
};

struct OnvifNamespace {
    char prefix[64], uri[256];
    unsigned active;
};

struct OnvifXml {
    XML_Parser parser;
    struct OnvifNamespace namespaces[64];
    unsigned namespace_count, depth, elements, failed, path[17], seen;
    unsigned match_seen, match_device, match_order, matches, found, field, used, reply_relation;
    char expected[46], text[2049];
};

static int
onvif_space(unsigned ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

static int
onvif_alpha(unsigned ch)
{
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
}

static int
onvif_hex(unsigned ch)
{
    return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f');
}

static int
onvif_uint(const char *p)
{
    uint32_t value = 0;
    unsigned digits = 0;
    while (onvif_space((unsigned char)*p)) p++;
    if (*p == '+') p++;
    while (*p >= '0' && *p <= '9') {
        unsigned digit = (unsigned)*p++ - '0';
        if (value > UINT32_MAX / 10 || (value == UINT32_MAX / 10 && digit > UINT32_MAX % 10)) return 0;
        value = value * 10 + digit; digits++;
    }
    while (onvif_space((unsigned char)*p)) p++;
    return digits && !*p;
}

static int
onvif_uri(const char *p, int http)
{
    const char *colon, *q, *end, *port = NULL;
    unsigned number = 0;
    if (!onvif_alpha((unsigned char)*p)) return 0;
    colon = strchr(p, ':');
    if (!colon || !colon[1]) return 0;
    for (q = p + 1; q < colon; q++)
        if (!onvif_alpha((unsigned char)*q) && !(*q >= '0' && *q <= '9') && !strchr("+.-", *q)) return 0;
    for (q = colon + 1; *q; q++) {
        unsigned ch = (unsigned char)*q;
        if (onvif_alpha(ch) || (ch >= '0' && ch <= '9') || strchr("-._~:/?#[]@!$&'()*+,;=", ch)) continue;
        if (ch == '%' && q[1] && q[2] && onvif_hex(q[1]) && onvif_hex(q[2])) { q += 2; continue; }
        return 0;
    }
    if (!http) return 1;
    if (!((colon - p == 4 || colon - p == 5) &&
          (p[0] | 32) == 'h' && (p[1] | 32) == 't' && (p[2] | 32) == 't' && (p[3] | 32) == 'p' &&
          (colon - p == 4 || (p[4] | 32) == 's')) || colon[1] != '/' || colon[2] != '/' || strchr(colon, '#')) return 0;
    p = colon + 3;
    end = p;
    while (*end && *end != '/' && *end != '?') end++;
    if (end == p) return 0;
    for (q = p; q < end; q++) if (*q == '@') return 0;
    if (*p == '[') {
        char address[64];
        const char *close = memchr(p, ']', (size_t)(end - p));
        ipv6address parsed;
        if (!close || close - p < 2 || (size_t)(close - p - 1) >= sizeof(address)) return 0;
        memcpy(address, p + 1, (size_t)(close - p - 1)); address[close - p - 1] = 0;
        parsed = massip_parse_ipv6(address);
        if (ipv6address_is_invalid(parsed)) return 0;
        if (close + 1 < end) { if (close[1] != ':') return 0; port = close + 2; }
    } else {
        for (q = p; q < end; q++) {
            if (*q == ':') { port = q + 1; break; }
            if (*q == '[' || *q == ']') return 0;
        }
        if (port == p + 1) return 0;
    }
    if (port) {
        if (port == end) return 0;
        for (q = port; q < end; q++) {
            unsigned digit = (unsigned char)*q - '0';
            if (digit > 9 || number > 6553 || (number == 6553 && digit > 5)) return 0;
            number = number * 10 + digit;
        }
        if (!number) return 0;
    }
    return 1;
}

static void
onvif_fail(struct OnvifXml *s)
{
    s->failed = 1;
    XML_StopParser(s->parser, XML_FALSE);
}

static const char *
onvif_qname(struct OnvifXml *s, const char *name, const char **local)
{
    const char *colon = strchr(name, ':'), *p;
    unsigned prefix_length = colon ? (unsigned)(colon - name) : 0, i;
    *local = colon ? colon + 1 : name;
    if (!**local || (colon && !prefix_length)) return NULL;
    for (p = name; *p; p++) {
        if (p == colon) continue;
        if ((p == name || p == *local) && !onvif_alpha((unsigned char)*p) && *p != '_') return NULL;
        if (!onvif_alpha((unsigned char)*p) && !(*p >= '0' && *p <= '9') && !strchr("_.-", *p)) return NULL;
    }
    for (i = s->namespace_count; i; i--) {
        struct OnvifNamespace *n = &s->namespaces[i - 1];
        if (n->active && strlen(n->prefix) == prefix_length && !memcmp(n->prefix, name, prefix_length)) return n->uri;
    }
    return colon ? NULL : "";
}

static int
onvif_list(struct OnvifXml *s, char *p, unsigned field)
{
    unsigned count = 0;
    while (*p) {
        char *start;
        while (onvif_space((unsigned char)*p)) p++;
        if (!*p) break;
        start = p;
        while (*p && !onvif_space((unsigned char)*p)) p++;
        if (*p) *p++ = 0;
        if (++count > 64) return 0;
        if (field == O_TYPES) {
            const char *local, *uri = onvif_qname(s, start, &local);
            if (!uri) return 0;
            if (!strcmp(uri, DEVICE_URI) && !strcmp(local, "Device")) s->match_device = 1;
        } else if (!onvif_uri(start, field == O_XADDRS)) return 0;
    }
    return count != 0;
}

static int
onvif_once(struct OnvifXml *s, unsigned *mask, unsigned bit)
{
    if (*mask & bit) { onvif_fail(s); return 0; }
    *mask |= bit;
    return 1;
}

static void XMLCALL
onvif_start(void *context, const XML_Char *name, const XML_Char **attrs)
{
    struct OnvifXml *s = context;
    unsigned parent, kind = O_UNKNOWN, count = 0, bit = 0, j;
    if (s->failed) return;
    while (attrs[count * 2]) if (++count > 32) { onvif_fail(s); return; }
    if (s->field || s->depth == 16 || ++s->elements > 256) { onvif_fail(s); return; }
    parent = s->path[s->depth];
    if (!s->depth) {
        if (strcmp(name, XNAME(SOAP_URI, "Envelope"))) { onvif_fail(s); return; }
        kind = O_ENVELOPE;
    } else if (parent == O_ENVELOPE) {
        if (!strcmp(name, XNAME(SOAP_URI, "Header")) && !(s->seen & 2)) { kind = O_HEADER; bit = 1; }
        else if (!strcmp(name, XNAME(SOAP_URI, "Body")) && (s->seen & 1)) { kind = O_BODY; bit = 2; }
        else { onvif_fail(s); return; }
        if (!onvif_once(s, &s->seen, bit)) return;
    } else if (parent == O_HEADER) {
        if (!strcmp(name, XNAME(ADDR_URI, "Action"))) { kind = O_ACTION; bit = 4; }
        else if (!strcmp(name, XNAME(ADDR_URI, "MessageID"))) { kind = O_ID; bit = 8; }
        else if (!strcmp(name, XNAME(ADDR_URI, "RelatesTo"))) {
            kind = O_RELATES; s->reply_relation = 1;
            for (j = 0; j < count; j++) if (!strcmp(attrs[j * 2], "RelationshipType")) {
                const char *local, *uri = onvif_qname(s, attrs[j * 2 + 1], &local);
                if (!uri) { onvif_fail(s); return; }
                s->reply_relation = !strcmp(uri, ADDR_URI) && !strcmp(local, "Reply");
            }
        } else if (!strcmp(name, XNAME(ADDR_URI, "To"))) { kind = O_TO; bit = 32; }
        else if (!strcmp(name, XNAME(DISC_URI, "AppSequence"))) {
            unsigned found = 0;
            kind = O_SEQUENCE; bit = 64;
            for (j = 0; j < count; j++) {
                const char *key = attrs[j * 2], *value = attrs[j * 2 + 1];
                if (!strcmp(key, "InstanceId") || !strcmp(key, "MessageNumber")) {
                    if (!onvif_uint(value)) { onvif_fail(s); return; }
                    found |= !strcmp(key, "InstanceId") ? 1 : 2;
                } else if (!strcmp(key, "SequenceId") && !onvif_uri(value, 0)) { onvif_fail(s); return; }
            }
            if (found != 3) { onvif_fail(s); return; }
        }
        if (bit && !onvif_once(s, &s->seen, bit)) return;
        for (j = 0; j < count; j++) {
            if (!strcmp(attrs[j * 2], XNAME(SOAP_URI, "role")) &&
                strcmp(attrs[j * 2 + 1], SOAP_URI "/role/ultimateReceiver")) { onvif_fail(s); return; }
            if (!strcmp(attrs[j * 2], XNAME(SOAP_URI, "mustUnderstand"))) {
                const char *v = attrs[j * 2 + 1];
                if (strcmp(v, "0") && strcmp(v, "false") && (kind == O_UNKNOWN || (strcmp(v, "1") && strcmp(v, "true")))) {
                    onvif_fail(s); return;
                }
            }
        }
    } else if (parent == O_BODY) {
        if (strcmp(name, XNAME(DISC_URI, "ProbeMatches")) || !onvif_once(s, &s->seen, 128)) { onvif_fail(s); return; }
        kind = O_MATCHES;
    } else if (parent == O_MATCHES && !strcmp(name, XNAME(DISC_URI, "ProbeMatch"))) {
        if (++s->matches > 16) { onvif_fail(s); return; }
        kind = O_MATCH; s->match_seen = s->match_device = s->match_order = 0;
    } else if (parent == O_MATCH) {
        if (!strcmp(name, XNAME(ADDR_URI, "EndpointReference"))) { kind = O_ENDPOINT; bit = 1; }
        else if (!strcmp(name, XNAME(DISC_URI, "Types"))) { kind = O_TYPES; bit = 4; }
        else if (!strcmp(name, XNAME(DISC_URI, "Scopes"))) { kind = O_SCOPES; bit = 8; }
        else if (!strcmp(name, XNAME(DISC_URI, "XAddrs"))) { kind = O_XADDRS; bit = 16; }
        else if (!strcmp(name, XNAME(DISC_URI, "MetadataVersion"))) { kind = O_METADATA; bit = 32; }
        if (bit) {
            unsigned order = kind == O_ENDPOINT ? 1 : kind - O_TYPES + 2;
            if (order <= s->match_order) { onvif_fail(s); return; }
            s->match_order = order;
            if (!onvif_once(s, &s->match_seen, bit)) return;
        }
    } else if (parent == O_ENDPOINT && !strcmp(name, XNAME(ADDR_URI, "Address"))) {
        kind = O_ADDRESS;
        if (!onvif_once(s, &s->match_seen, 2)) return;
    } else if (parent == O_SEQUENCE) { onvif_fail(s); return; }
    s->path[++s->depth] = kind;
    if ((kind >= O_ACTION && kind <= O_TO) || kind >= O_ADDRESS) {
        s->field = kind; s->used = 0;
    }
}

static void XMLCALL
onvif_end(void *context, const XML_Char *name)
{
    struct OnvifXml *s = context;
    unsigned kind;
    char *text, *end;
    (void)name;
    if (s->failed) return;
    kind = s->path[s->depth];
    if (s->field) {
        s->text[s->used] = 0;
        text = s->text;
        while (onvif_space((unsigned char)*text)) text++;
        end = text + strlen(text);
        while (end > text && onvif_space((unsigned char)end[-1])) *--end = 0;
        if ((kind == O_ACTION && strcmp(text, DISC_URI "/ProbeMatches")) ||
            (kind == O_TO && strcmp(text, ADDR_URI "/role/anonymous")) ||
            ((kind == O_ID || kind == O_ADDRESS || kind == O_RELATES) && !onvif_uri(text, 0)) ||
            (kind == O_METADATA && !onvif_uint(text)) ||
            ((kind == O_TYPES || kind == O_SCOPES || kind == O_XADDRS) && !onvif_list(s, text, kind))) {
            onvif_fail(s); return;
        }
        if (kind == O_RELATES && s->reply_relation) {
            if (strcmp(text, s->expected) || !onvif_once(s, &s->seen, 16)) { onvif_fail(s); return; }
        }
        s->field = 0;
    }
    if (kind == O_ENDPOINT && !(s->match_seen & 2)) { onvif_fail(s); return; }
    if (kind == O_MATCH) {
        if ((s->match_seen & 35) != 35) { onvif_fail(s); return; }
        if (s->match_device && s->match_seen == 63) s->found++;
    }
    s->depth--;
}

static void XMLCALL
onvif_text(void *context, const XML_Char *text, int length)
{
    struct OnvifXml *s = context;
    int i;
    if (s->failed) return;
    if (s->field) {
        if (length < 0 || (unsigned)length > 2048 - s->used) { onvif_fail(s); return; }
        memcpy(s->text + s->used, text, (size_t)length); s->used += (unsigned)length;
    } else if (s->path[s->depth] != O_UNKNOWN) {
        for (i = 0; i < length; i++) if (!onvif_space((unsigned char)text[i])) { onvif_fail(s); return; }
    }
}

static void XMLCALL
onvif_namespace_start(void *context, const XML_Char *prefix, const XML_Char *uri)
{
    struct OnvifXml *s = context;
    struct OnvifNamespace *n;
    if (s->failed) return;
    if (!prefix) prefix = "";
    if (!uri) uri = "";
    if (s->namespace_count == 64 || strlen(prefix) >= 64 || strlen(uri) >= 256) { onvif_fail(s); return; }
    n = &s->namespaces[s->namespace_count++];
    memcpy(n->prefix, prefix, strlen(prefix) + 1);
    memcpy(n->uri, uri, strlen(uri) + 1); n->active = 1;
}

static void XMLCALL
onvif_namespace_end(void *context, const XML_Char *prefix)
{
    struct OnvifXml *s = context;
    unsigned i;
    if (s->failed) return;
    if (!prefix) prefix = "";
    for (i = s->namespace_count; i; i--)
        if (s->namespaces[i - 1].active && !strcmp(s->namespaces[i - 1].prefix, prefix)) {
            s->namespaces[i - 1].active = 0; return;
        }
    onvif_fail(s);
}

static void XMLCALL
onvif_doctype(void *context, const XML_Char *name, const XML_Char *system_id,
               const XML_Char *public_id, int internal)
{
    (void)name; (void)system_id; (void)public_id; (void)internal;
    onvif_fail(context);
}

static int XMLCALL
onvif_external(XML_Parser parser, const XML_Char *context, const XML_Char *base,
                const XML_Char *system_id, const XML_Char *public_id)
{
    (void)parser; (void)context; (void)base; (void)system_id; (void)public_id;
    return XML_STATUS_ERROR;
}

static void XMLCALL
onvif_declaration(void *context, const XML_Char *version, const XML_Char *encoding, int standalone)
{
    struct OnvifXml *s = context;
    unsigned i;
    (void)standalone;
    if (s->failed) return;
    if (!version || strcmp(version, "1.0")) { onvif_fail(s); return; }
    if (!encoding) return;
    if (strlen(encoding) != 5) { onvif_fail(s); return; }
    for (i = 0; i < 5; i++) if ((encoding[i] | 32) != "utf-8"[i]) { onvif_fail(s); return; }
}

static int
onvif_message_id(uint64_t cookie, const struct UdpProbeTarget *target, char id[46])
{
    unsigned char bytes[32];
    unsigned i, offset = 9;
    static const char hex[] = "0123456789abcdef";
    if (!udp_probe_derive_target("onvif-message", cookie, 3702, target, bytes)) return 0;
    bytes[6] = (bytes[6] & 15) | 0x40; bytes[8] = (bytes[8] & 63) | 0x80;
    memcpy(id, "urn:uuid:", 9);
    for (i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) id[offset++] = '-';
        id[offset++] = hex[bytes[i] >> 4]; id[offset++] = hex[bytes[i] & 15];
    }
    id[offset] = 0;
    return 1;
}

int
onvif_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                     struct UdpPreparedProbe *result)
{
    char id[46];
    int length;
    if (!onvif_message_id(cookie, target, id)) return 0;
    length = snprintf((char *)result->payload, sizeof(result->payload),
        "<s:Envelope xmlns:s='" SOAP_URI "' xmlns:a='" ADDR_URI "' xmlns:d='" DISC_URI "'>"
        "<s:Header><a:Action>" DISC_URI "/Probe</a:Action><a:MessageID>%s</a:MessageID>"
        "<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To></s:Header>"
        "<s:Body><d:Probe/></s:Body></s:Envelope>", id);
    if (length < 0 || (unsigned)length >= sizeof(result->payload)) return 0;
    result->length = (unsigned)length;
    return 1;
}

int
onvif_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie,
                      const struct UdpProbeTarget *target)
{
    struct OnvifXml state = {0};
    int parsed, valid;
    if (!length || length > 8192 || !onvif_message_id(cookie, target, state.expected)) return 0;
    state.parser = XML_ParserCreateNS("UTF-8", '\x1f');
    if (!state.parser) return 0;
    XML_SetUserData(state.parser, &state);
    XML_SetElementHandler(state.parser, onvif_start, onvif_end);
    XML_SetCharacterDataHandler(state.parser, onvif_text);
    XML_SetNamespaceDeclHandler(state.parser, onvif_namespace_start, onvif_namespace_end);
    XML_SetStartDoctypeDeclHandler(state.parser, onvif_doctype);
    XML_SetExternalEntityRefHandler(state.parser, onvif_external);
    XML_SetXmlDeclHandler(state.parser, onvif_declaration);
    XML_SetParamEntityParsing(state.parser, XML_PARAM_ENTITY_PARSING_NEVER);
    parsed = XML_Parse(state.parser, (const char *)data, (int)length, XML_TRUE);
    valid = parsed == XML_STATUS_OK && !state.failed && !state.depth && state.seen == 255 && state.found;
    XML_ParserFree(state.parser);
    return valid;
}
#endif
