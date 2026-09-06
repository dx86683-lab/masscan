#include "proto-udp-plex.h"
#ifdef UDP_EXTENDED_PROBES
#include <string.h>
#include <expat.h>

struct PlexXml {
    XML_Parser parser;
    unsigned depth, count, failed;
};

static void
plex_xml_fail(struct PlexXml *s)
{
    s->failed = 1;
    XML_StopParser(s->parser, XML_FALSE);
}

static void XMLCALL
plex_xml_start(void *context, const XML_Char *name, const XML_Char **attributes)
{
    struct PlexXml *s = context;
    unsigned i = 0;
    if (s->failed) return;
    while (attributes[i * 2]) if (++i > 32) { plex_xml_fail(s); return; }
    if (++s->depth > 16 || ++s->count > 256 ||
        (s->depth == 1 && strcmp(name, "PlexMediaServer"))) plex_xml_fail(s);
}

static void XMLCALL
plex_xml_end(void *context, const XML_Char *name)
{
    struct PlexXml *s = context;
    (void)name;
    if (!s->failed) s->depth--;
}

static void XMLCALL
plex_xml_doctype(void *context, const XML_Char *name, const XML_Char *system_id,
                  const XML_Char *public_id, int internal)
{
    (void)name; (void)system_id; (void)public_id; (void)internal;
    plex_xml_fail(context);
}

static int XMLCALL
plex_xml_external(XML_Parser parser, const XML_Char *context, const XML_Char *base,
                   const XML_Char *system_id, const XML_Char *public_id)
{
    (void)parser; (void)context; (void)base; (void)system_id; (void)public_id;
    return XML_STATUS_ERROR;
}

static int
plex_xml(const char *data, unsigned length)
{
    struct PlexXml s;
    int valid;
    memset(&s, 0, sizeof(s));
    s.parser = XML_ParserCreateNS("UTF-8", '|');
    if (!s.parser) return 0;
    XML_SetUserData(s.parser, &s);
    XML_SetElementHandler(s.parser, plex_xml_start, plex_xml_end);
    XML_SetStartDoctypeDeclHandler(s.parser, plex_xml_doctype);
    XML_SetExternalEntityRefHandler(s.parser, plex_xml_external);
    XML_SetParamEntityParsing(s.parser, XML_PARAM_ENTITY_PARSING_NEVER);
    valid = XML_Parse(s.parser, data, (int)length, XML_TRUE) == XML_STATUS_OK &&
        !s.failed && !s.depth && s.count;
    XML_ParserFree(s.parser);
    return valid;
}

static int
plex_equal(const char *a, const char *b)
{
    while (*a && *b) {
        unsigned x = (unsigned char)*a++, y = (unsigned char)*b++;
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return 0;
    }
    return *a == *b;
}

static int
plex_text(const char *p)
{
    const unsigned char *s = (const unsigned char *)p;
    if (!*s || strlen(p) > 255) return 0;
    while (*s) {
        unsigned c = *s++, count, minimum;
        if (c < 128) { if (c < 32 || c == 127) return 0; continue; }
        if (c >= 0xc2 && c <= 0xdf) { count = 1; c &= 31; minimum = 128; }
        else if (c >= 0xe0 && c <= 0xef) { count = 2; c &= 15; minimum = 2048; }
        else if (c >= 0xf0 && c <= 0xf4) { count = 3; c &= 7; minimum = 65536; }
        else return 0;
        while (count--) {
            if ((*s & 0xc0) != 0x80) return 0;
            c = c << 6 | (*s++ & 63);
        }
        if (c < minimum || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) return 0;
    }
    return 1;
}

static int
plex_decimal(const char *p, uint32_t maximum, uint32_t *value)
{
    *value = 0;
    if (!*p) return 0;
    while (*p) {
        unsigned digit = (unsigned char)*p++ - '0';
        if (digit > 9 || *value > maximum / 10 ||
            (*value == maximum / 10 && digit > maximum % 10)) return 0;
        *value = *value * 10 + digit;
    }
    return 1;
}

int
plex_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                     struct UdpPreparedProbe *result)
{
    (void)cookie; (void)target;
    memcpy(result->payload, "M-SEARCH * HTTP/1.1\r\n\r\n", 23);
    result->length = 23;
    return 1;
}

int
plex_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    static const char *fields[] = {"Content-Type", "Name", "Resource-Identifier", "Port",
                                   "Version", "Updated-At", "Host", "Content-Length"};
    char buffer[4097], *line, *body, *end;
    unsigned seen = 0, count = 0;
    uint32_t body_length = 0;
    (void)cookie;
    if (length < 19 || length > 4096 || memchr(data, 0, length) ||
        memcmp(data, "HTTP/1.0 200 OK\r\n", 17)) return 0;
    memcpy(buffer, data, length); buffer[length] = 0;
    line = buffer + 17;
    for (;;) {
        char *colon, *value, *p;
        unsigned field;
        end = strstr(line, "\r\n");
        if (!end || end - buffer > 2046) return 0;
        if (end == line) { body = end + 2; break; }
        if (++count > 32) return 0;
        *end = 0;
        colon = strchr(line, ':');
        if (!colon || colon == line) return 0;
        *colon = 0;
        for (p = line; *p; p++) {
            unsigned c = (unsigned char)*p;
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-')) return 0;
        }
        value = colon + 1;
        while (*value == ' ' || *value == '\t') value++;
        p = end;
        while (p > value && (p[-1] == ' ' || p[-1] == '\t')) *--p = 0;
        if (!plex_text(value)) return 0;
        for (field = 0; field < 8; field++) if (plex_equal(line, fields[field])) break;
        if (field < 8) {
            uint32_t number;
            if (seen & (1u << field)) return 0;
            seen |= 1u << field;
            if (field == 0 && !plex_equal(value, "plex/media-server")) return 0;
            if (field == 2)
                for (p = value; *p; p++) if ((unsigned char)*p <= 32 || (unsigned char)*p > 126) return 0;
            if (field == 3 && (!plex_decimal(value, 65535, &number) || !number)) return 0;
            if (field == 5 && !plex_decimal(value, UINT32_MAX, &number)) return 0;
            if (field == 7 && !plex_decimal(value, 4096, &body_length)) return 0;
        }
        line = end + 2;
    }
    if ((seen & 7) != 7 || body_length != length - (unsigned)(body - buffer)) return 0;
    return body_length == 0 || plex_xml(body, body_length);
}
#endif
