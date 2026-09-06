#include "proto-udp-ssdp.h"
#include "massip-parse.h"
#include "util-safefunc.h"

static int
equal_ci(const char *a, const char *b)
{
    while (*a && *b) {
        unsigned x = (unsigned char)*a++, y = (unsigned char)*b++;
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return 0;
    }
    return *a == *b;
}

static char *
trim_space(char *p)
{
    char *end;
    while (*p == ' ' || *p == '\t') p++;
    end = p + strlen(p);
    while (end > p && (end[-1] == ' ' || end[-1] == '\t')) *--end = 0;
    return p;
}

static int
decimal(const char *p, uint32_t minimum, uint32_t maximum)
{
    uint32_t value = 0;
    if (!*p) return 0;
    while (*p) {
        unsigned digit = (unsigned char)*p++ - '0';
        if (digit > 9 || value > maximum / 10 ||
            (value == maximum / 10 && digit > maximum % 10)) return 0;
        value = value * 10 + digit;
    }
    return value >= minimum;
}

static int
hex_digit(unsigned ch)
{
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
}

static int
uri_text(const char *p, int host)
{
    while (*p) {
        unsigned ch = (unsigned char)*p++;
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || strchr("-._~!$&'()*+,;=", ch)) continue;
        if (ch == '%' && p[0] && p[1] && hex_digit(p[0]) && hex_digit(p[1])) { p += 2; continue; }
        if (!host && strchr(":@/?", ch)) continue;
        return 0;
    }
    return 1;
}

static int
http_location(char *value)
{
    char *authority, *end, *port = NULL, *separator;
    char scheme[6];
    char saved;
    separator = strstr(value, "://");
    if (!separator || separator - value < 4 || separator - value > 5) return 0;
    memcpy(scheme, value, separator - value);
    scheme[separator - value] = 0;
    if (!equal_ci(scheme, "http") && !equal_ci(scheme, "https")) return 0;
    authority = separator + 3;
    end = authority;
    while (*end && *end != '/' && *end != '?') end++;
    if (!uri_text(end, 0)) return 0;
    saved = *end;
    *end = 0;
    if (*authority == '[') {
        char *close = strchr(authority, ']');
        ipv6address address;
        unsigned i;
        if (!close || close == authority + 1) return 0;
        *close = 0;
        for (i = 1; authority[i]; i++)
            if (!hex_digit(authority[i]) && authority[i] != ':' && authority[i] != '.') return 0;
        address = massip_parse_ipv6(authority + 1);
        if (ipv6address_is_invalid(address)) return 0;
        if (close[1]) {
            if (close[1] != ':') return 0;
            port = close + 2;
        }
    } else {
        port = strchr(authority, ':');
        if (port) *port++ = 0;
        if (!*authority || !uri_text(authority, 1)) return 0;
    }
    if (port && !decimal(port, 1, 65535)) return 0;
    *end = saved;
    return 1;
}

static int
cache_age(char *value)
{
    unsigned seen = 0;
    char *p = value;
    while (*p) {
        char *start = p, *eq;
        unsigned quote = 0;
        while (*p && (quote || *p != ',')) {
            if (*p == '\\' && quote && p[1]) { p += 2; continue; }
            if (*p == '"') quote ^= 1;
            p++;
        }
        if (quote) return 0;
        if (*p) *p++ = 0;
        start = trim_space(start);
        if (!*start) return 0;
        eq = strchr(start, '=');
        if (!eq) continue;
        *eq++ = 0;
        if (!equal_ci(trim_space(start), "max-age")) continue;
        if (++seen != 1 || !decimal(trim_space(eq), 0, UINT32_MAX)) return 0;
    }
    return seen == 1;
}

static int
server_version(char *value)
{
    char *upnp, *product, *slash, *p;
    upnp = strchr(value, ' ');
    if (!upnp) return 0;
    *upnp++ = 0;
    upnp = trim_space(upnp);
    slash = strchr(value, '/');
    if (!slash || slash == value || !slash[1]) return 0;
    product = strchr(upnp, ' ');
    if (!product) return 0;
    *product++ = 0;
    product = trim_space(product);
    slash = strchr(product, '/');
    if (!slash || slash == product || !slash[1]) return 0;
    for (p = product; *p; p++) if (*p == ' ' || *p == '\t') return 0;
    if (!strcmp(upnp, "UPnP/1.0")) return 1;
    if (!strcmp(upnp, "UPnP/1.1") || !strcmp(upnp, "UPnP/2.0")) return 2;
    return 0;
}

static int
root_usn(const char *value)
{
    unsigned i;
    if (strlen(value) != 58 || strncmp(value, "uuid:", 5) ||
        strcmp(value + 41, "::upnp:rootdevice")) return 0;
    for (i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i + 5] != '-') return 0;
        } else if (!hex_digit(value[i + 5])) return 0;
    }
    return 1;
}

int
ssdp_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                   struct UdpPreparedProbe *result)
{
    struct ipaddress_formatted destination;
    char host[64];
    int length;
    (void)cookie;
    if (!target || (target->destination.version != 4 && target->destination.version != 6)) return 0;
    destination = ipaddress_fmt(target->destination);
    snprintf(host, sizeof(host), target->destination.version == 6 ? "[%s]" : "%s", destination.string);
    length = snprintf((char *)result->payload, sizeof(result->payload),
        "M-SEARCH * HTTP/1.1\r\nHOST: %s:1900\r\nMAN: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\n\r\n", host);
    if (length < 0 || (unsigned)length >= sizeof(result->payload)) return 0;
    result->length = (unsigned)length;
    return 1;
}

int
ssdp_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    static const char *names[] = {"cache-control", "ext", "location", "server", "st", "usn",
        "bootid.upnp.org", "configid.upnp.org", "searchport.upnp.org"};
    char buffer[8193], *headers[9] = {0}, *p, *end;
    unsigned i, lines = 0, finished = 0;
    int version;
    (void)cookie;
    if (length < 19 || length > 8192 || memcmp(data, "HTTP/1.1 200 OK\r\n", 17)) return 0;
    for (i = 0; i < length; i++)
        if (!data[i] || (data[i] < 32 && data[i] != '\r' && data[i] != '\n' && data[i] != '\t') || data[i] == 127)
            return 0;
    memcpy(buffer, data, length);
    buffer[length] = 0;
    p = buffer + 17;
    end = buffer + length;
    while (p < end && lines++ < 64) {
        char *line = p, *colon, *value;
        while (p < end && *p != '\r' && *p != '\n') p++;
        if (end - p < 2 || p[0] != '\r' || p[1] != '\n') return 0;
        *p = 0;
        p += 2;
        if (!*line) { finished = p == end; break; }
        colon = strchr(line, ':');
        if (!colon || colon == line) return 0;
        *colon = 0;
        for (value = line; *value; value++)
            if (!( (*value >= 'A' && *value <= 'Z') || (*value >= 'a' && *value <= 'z') ||
                  (*value >= '0' && *value <= '9') || strchr("!#$%&'*+-.^_`|~", *value))) return 0;
        value = trim_space(colon + 1);
        for (i = 0; i < 9; i++) {
            if (!equal_ci(line, names[i])) continue;
            if (headers[i]) return 0;
            headers[i] = value;
        }
    }
    if (!finished) return 0;
    for (i = 0; i < 6; i++) if (!headers[i]) return 0;
    version = server_version(headers[3]);
    if (!version || !cache_age(headers[0]) || *headers[1] || !http_location(headers[2]) ||
        strcmp(headers[4], "upnp:rootdevice") || !root_usn(headers[5])) return 0;
    if (version > 1 && !headers[6]) return 0;
    if (headers[6] && !decimal(headers[6], 0, 0x7fffffff)) return 0;
    if (headers[7] && !decimal(headers[7], 0, 0xffffff)) return 0;
    if (headers[8] && !decimal(headers[8], 1, 65535)) return 0;
    return 1;
}
