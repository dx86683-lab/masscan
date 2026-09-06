#include "proto-udp-jenkins.h"
#ifdef UDP_EXTENDED_PROBES
#include <expat.h>
#include <string.h>

struct JenkinsXml {
    XML_Parser parser;
    unsigned depth, elements, namespaces, failed, seen, field, used;
    char text[2049];
};

static void
jenkins_fail(struct JenkinsXml *state)
{
    state->failed = 1;
    XML_StopParser(state->parser, XML_FALSE);
}

static void XMLCALL
jenkins_start(void *context, const XML_Char *name, const XML_Char **attributes)
{
    struct JenkinsXml *s = context;
    unsigned count = 0, field = 0;
    if (s->failed) return;
    while (attributes[count * 2]) {
        if (++count > 32) { jenkins_fail(s); return; }
    }
    if (++s->depth > 16 || ++s->elements > 256 || s->field) { jenkins_fail(s); return; }
    if (s->depth == 1 && strcmp(name, "hudson")) { jenkins_fail(s); return; }
    if (s->depth != 2) return;
    if (!strcmp(name, "version")) field = 1;
    else if (!strcmp(name, "url")) field = 2;
    else if (!strcmp(name, "server-id")) field = 4;
    else if (!strcmp(name, "slave-port")) field = 8;
    if (!field) return;
    if (s->seen & field) { jenkins_fail(s); return; }
    s->seen |= field;
    s->field = field;
    s->used = 0;
}

static void XMLCALL
jenkins_end(void *context, const XML_Char *name)
{
    struct JenkinsXml *s = context;
    unsigned i, nonspace = 0, port = 0;
    (void)name;
    if (s->failed) return;
    if (s->depth == 2 && s->field) {
        if (s->field == 1) {
            if (!s->used || s->used > 128) { jenkins_fail(s); return; }
            for (i = 0; i < s->used; i++) {
                unsigned ch = (unsigned char)s->text[i];
                if (ch < 32 || ch > 126) { jenkins_fail(s); return; }
                nonspace |= ch != ' ';
            }
            if (!nonspace) { jenkins_fail(s); return; }
        } else if (s->field == 8) {
            if (!s->used) { jenkins_fail(s); return; }
            for (i = 0; i < s->used; i++) {
                unsigned digit = (unsigned char)s->text[i] - '0';
                if (digit > 9 || port > 6553 || (port == 6553 && digit > 5)) { jenkins_fail(s); return; }
                port = port * 10 + digit;
            }
            if (!port) { jenkins_fail(s); return; }
        }
        s->field = 0;
    }
    s->depth--;
}

static void XMLCALL
jenkins_text(void *context, const XML_Char *text, int length)
{
    struct JenkinsXml *s = context;
    int i;
    if (s->failed) return;
    if (!s->field) {
        if (s->depth <= 1)
            for (i = 0; i < length; i++)
                if (text[i] != ' ' && text[i] != '\t' && text[i] != '\r' && text[i] != '\n') {
                    jenkins_fail(s); return;
                }
        return;
    }
    if (length < 0 || (unsigned)length > 2048 - s->used) { jenkins_fail(s); return; }
    memcpy(s->text + s->used, text, length);
    s->used += (unsigned)length;
}

static void XMLCALL
jenkins_doctype(void *context, const XML_Char *name, const XML_Char *system_id,
                const XML_Char *public_id, int internal)
{
    (void)name; (void)system_id; (void)public_id; (void)internal;
    jenkins_fail(context);
}

static int XMLCALL
jenkins_external(XML_Parser parser, const XML_Char *context, const XML_Char *base,
                 const XML_Char *system_id, const XML_Char *public_id)
{
    (void)parser; (void)context; (void)base; (void)system_id; (void)public_id;
    return XML_STATUS_ERROR;
}

static void XMLCALL
jenkins_namespace(void *context, const XML_Char *prefix, const XML_Char *uri)
{
    struct JenkinsXml *s = context;
    (void)prefix; (void)uri;
    if (!s->failed && ++s->namespaces > 64) jenkins_fail(s);
}

static void XMLCALL
jenkins_declaration(void *context, const XML_Char *version, const XML_Char *encoding, int standalone)
{
    struct JenkinsXml *s = context;
    unsigned i;
    (void)standalone;
    if (s->failed) return;
    if (!version || strcmp(version, "1.0")) { jenkins_fail(s); return; }
    if (!encoding) return;
    if (strlen(encoding) != 5) { jenkins_fail(s); return; }
    for (i = 0; i < 5; i++)
        if (((unsigned char)encoding[i] | 32) != (unsigned char)"utf-8"[i]) { jenkins_fail(s); return; }
}

int
jenkins_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                      struct UdpPreparedProbe *result)
{
    (void)cookie; (void)target;
    result->payload[0] = 0;
    result->length = 1;
    return 1;
}

int
jenkins_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    struct JenkinsXml state = {0};
    int parsed, valid;
    (void)cookie;
    if (!length || length > 8192) return 0;
    state.parser = XML_ParserCreateNS("UTF-8", '\x1f');
    if (!state.parser) return 0;
    XML_SetUserData(state.parser, &state);
    XML_SetElementHandler(state.parser, jenkins_start, jenkins_end);
    XML_SetCharacterDataHandler(state.parser, jenkins_text);
    XML_SetStartDoctypeDeclHandler(state.parser, jenkins_doctype);
    XML_SetExternalEntityRefHandler(state.parser, jenkins_external);
    XML_SetStartNamespaceDeclHandler(state.parser, jenkins_namespace);
    XML_SetXmlDeclHandler(state.parser, jenkins_declaration);
    XML_SetParamEntityParsing(state.parser, XML_PARAM_ENTITY_PARSING_NEVER);
    parsed = XML_Parse(state.parser, (const char *)data, (int)length, XML_TRUE);
    valid = parsed == XML_STATUS_OK && !state.failed && !state.depth && (state.seen & 1);
    XML_ParserFree(state.parser);
    return valid;
}
#endif
