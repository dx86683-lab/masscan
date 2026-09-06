#include "proto-udp-sip.h"
#include "util-safefunc.h"
#include <string.h>

static int
text_equal(const char *a, const char *b)
{
    while (*a && *b) {
        unsigned x = (unsigned char)*a++;
        unsigned y = (unsigned char)*b++;
        if (x >= 'A' && x <= 'Z') x += 'a' - 'A';
        if (y >= 'A' && y <= 'Z') y += 'a' - 'A';
        if (x != y) return 0;
    }
    return *a == *b;
}

static char *
trim(char *value)
{
    char *end;
    while (*value == ' ' || *value == '\t') value++;
    end = value + strlen(value);
    while (end > value && (end[-1] == ' ' || end[-1] == '\t')) end--;
    *end = 0;
    return value;
}

int
sip_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                   struct UdpPreparedProbe *result)
{
    struct ipaddress_formatted source, destination;
    char from[64], to[64];
    int length;

    if (!target || (target->source.version != 4 && target->source.version != 6) ||
        target->source.version != target->destination.version ||
        target->source_port == 0 || target->source_port > 65535)
        return 0;
    source = ipaddress_fmt(target->source);
    destination = ipaddress_fmt(target->destination);
    snprintf(from, sizeof(from), target->source.version == 6 ? "[%s]" : "%s", source.string);
    snprintf(to, sizeof(to), target->destination.version == 6 ? "[%s]" : "%s", destination.string);
    length = snprintf((char *)result->payload, sizeof(result->payload),
        "OPTIONS sip:%s:%u SIP/2.0\r\n"
        "Via: SIP/2.0/UDP %s:%u;branch=z9hG4bK%08x;rport\r\n"
        "Max-Forwards: 0\r\nFrom: <sip:probe@%s>;tag=%08x\r\n"
        "To: <sip:%s:%u>\r\nCall-ID: scan-%08x@scan.invalid\r\n"
        "CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
        to, result->port, from, target->source_port, (unsigned)(uint32_t)cookie,
        from, (unsigned)(uint32_t)cookie, to, result->port, (unsigned)(uint32_t)cookie);
    if (length < 0 || (unsigned)length >= sizeof(result->payload)) return 0;
    result->length = (unsigned)length;
    return 1;
}

/* Read CRLF lines and unfold continuation lines within one bounded header. */
static int
read_header(const unsigned char *data, unsigned length, unsigned *offset,
            char *line, unsigned capacity)
{
    unsigned used = 0;
    int again;
    do {
        again = 0;
        while (*offset < length && data[*offset] != '\r') {
            if (data[*offset] == '\n' || data[*offset] == 0 || used + 1 >= capacity)
                return 0;
            line[used++] = (char)data[(*offset)++];
        }
        if (*offset + 1 >= length || data[*offset + 1] != '\n') return 0;
        *offset += 2;
        if (used && *offset < length &&
            (data[*offset] == ' ' || data[*offset] == '\t')) {
            while (*offset < length && (data[*offset] == ' ' || data[*offset] == '\t'))
                (*offset)++;
            if (used + 1 >= capacity) return 0;
            line[used++] = ' ';
            again = 1;
        }
    } while (again);
    line[used] = 0;
    return 1;
}

static int
via_matches(char *value, const char *expected)
{
    char *p = value;
    int found = 0;
    int quoted = 0;
    char transport[12];
    if (strlen(value) < 12 || (value[11] != ' ' && value[11] != '\t')) return 0;
    memcpy(transport, value, 11);
    transport[11] = 0;
    if (!text_equal(transport, "SIP/2.0/UDP")) return 0;
    while (*p) {
        if (*p == '"') quoted = !quoted;
        if (*p == '\\' && quoted && p[1]) { p += 2; continue; }
        if (*p == ',' && !quoted) break;
        if (*p == ';' && !quoted) {
            char *name = ++p;
            char *end;
            char saved;
            while (*p && *p != '=' && *p != ';' && *p != ',') p++;
            if (*p != '=') continue;
            *p++ = 0;
            if (!text_equal(trim(name), "branch")) continue;
            end = p;
            while (*end && *end != ';' && *end != ',') end++;
            saved = *end;
            *end = 0;
            if (++found != 1 || strcmp(trim(p), expected) != 0) return 0;
            *end = saved;
            p = end;
            continue;
        }
        p++;
    }
    return found == 1 && !quoted;
}

int
sip_probe_classify(const unsigned char *response, unsigned length, uint64_t cookie)
{
    char line[UDP_PROBE_MAX_PAYLOAD];
    char expected_branch[32], expected_id[48];
    unsigned offset = 0;
    unsigned seen = 0, body_length = 0;
    int have_length = 0;

    if (length < 16 || !read_header(response, length, &offset, line, sizeof(line))) return 0;
    if (strlen(line) < 12 || line[7] != ' ' ||
        line[8] < '1' || line[8] > '6' || line[9] < '0' || line[9] > '9' ||
        line[10] < '0' || line[10] > '9' || line[11] != ' ') return 0;
    line[7] = 0;
    if (!text_equal(line, "SIP/2.0")) return 0;
    snprintf(expected_branch, sizeof(expected_branch), "z9hG4bK%08x", (unsigned)(uint32_t)cookie);
    snprintf(expected_id, sizeof(expected_id), "scan-%08x@scan.invalid", (unsigned)(uint32_t)cookie);
    while (offset < length) {
        char *colon, *name, *value;
        if (!read_header(response, length, &offset, line, sizeof(line))) return 0;
        if (!line[0]) return seen == 7 && (!have_length || body_length == length - offset);
        colon = strchr(line, ':');
        if (!colon) return 0;
        *colon = 0;
        name = trim(line);
        value = trim(colon + 1);
        if (text_equal(name, "Via") || text_equal(name, "v")) {
            if (!(seen & 1)) {
                if (!via_matches(value, expected_branch)) return 0;
                seen |= 1;
            }
        } else if (text_equal(name, "Call-ID") || text_equal(name, "i")) {
            if ((seen & 2) || strcmp(value, expected_id)) return 0;
            seen |= 2;
        } else if (text_equal(name, "CSeq")) {
            unsigned number = 0, digits = 0;
            if (seen & 4) return 0;
            while (*value >= '0' && *value <= '9') {
                if (++digits > 10 || number > 214748364U) return 0;
                number = number * 10 + *value++ - '0';
            }
            if (!digits || number != 1 || (*value != ' ' && *value != '\t') ||
                strcmp(trim(value), "OPTIONS")) return 0;
            seen |= 4;
        } else if (text_equal(name, "Content-Length") || text_equal(name, "l")) {
            unsigned digits = 0;
            if (have_length) return 0;
            have_length = 1;
            while (*value >= '0' && *value <= '9') {
                if (++digits > 5) return 0;
                body_length = body_length * 10 + *value++ - '0';
            }
            if (!digits || *value) return 0;
        }
    }
    return 0;
}
