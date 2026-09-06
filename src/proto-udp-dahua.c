#include "proto-udp-dahua.h"
#ifdef UDP_EXTENDED_PROBES
#include "proto-udp-discovery-fields.h"
#include <jansson.h>
#include <string.h>

static uint32_t
dahua_u32(const unsigned char *data)
{
    return (uint32_t)data[0] | (uint32_t)data[1] << 8 | (uint32_t)data[2] << 16 | (uint32_t)data[3] << 24;
}

int
dahua_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                    struct UdpPreparedProbe *result)
{
    static const char query[] = "{\"method\":\"DHDiscover.search\",\"params\":{\"mac\":\"\",\"uni\":1}}";
    unsigned i, length = sizeof(query) - 1;
    (void)cookie; (void)target;
    memset(result->payload, 0, 32);
    result->payload[0] = 32; memcpy(result->payload + 4, "DHIP", 4);
    for (i = 0; i < 4; i++) result->payload[16 + i] = result->payload[24 + i] = (unsigned char)(length >> (8 * i));
    memcpy(result->payload + 32, query, length);
    result->length = 32 + length;
    return 1;
}

static int
dahua_json_depth(const unsigned char *data, unsigned length)
{
    unsigned i, depth = 0, string = 0, escaped = 0;
    for (i = 0; i < length; i++) {
        unsigned c = data[i];
        if (!c) return 0;
        if (string) {
            if (escaped) escaped = 0;
            else if (c == '\\') escaped = 1;
            else if (c == '"') string = 0;
        } else if (c == '"') string = 1;
        else if (c == '{' || c == '[') { if (++depth > 16) return 0; }
        else if (c == '}' || c == ']') { if (!depth) return 0; depth--; }
    }
    return !depth && !string;
}

static int
dahua_json_budget(const json_t *value, unsigned depth, unsigned *nodes)
{
    if (depth > 16 || *nodes == 256) return 0;
    (*nodes)++;
    if (json_is_string(value)) return json_string_length(value) <= 512;
    if (json_is_array(value)) {
        size_t i;
        for (i = 0; i < json_array_size(value); i++)
            if (!dahua_json_budget(json_array_get(value, i), depth + 1, nodes)) return 0;
    } else if (json_is_object(value)) {
        const char *key;
        json_t *child;
        json_object_foreach((json_t *)value, key, child) {
            if (strlen(key) > 128 || !dahua_json_budget(child, depth + 1, nodes)) return 0;
        }
    }
    return 1;
}

static int
dahua_identity(const json_t *value)
{
    const unsigned char *text;
    size_t i, length;
    unsigned nonspace = 0;
    if (!json_is_string(value)) return 0;
    length = json_string_length(value); text = (const unsigned char *)json_string_value(value);
    if (!length || length > 255) return 0;
    for (i = 0; i < length; i++) {
        if (text[i] < 32 || text[i] == 127) return 0;
        nonspace |= text[i] != ' ';
    }
    return nonspace != 0;
}

int
dahua_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie)
{
    json_t *root, *method, *params, *info, *address, *mac;
    unsigned nodes = 0, has_address = 0;
    int valid = 0;
    (void)cookie;
    if (length < 34 || length > 8192 || dahua_u32(data) != 32 || memcmp(data + 4, "DHIP", 4) ||
        dahua_u32(data + 16) != length - 32 || dahua_u32(data + 20) ||
        dahua_u32(data + 24) != length - 32 || dahua_u32(data + 28) ||
        !dahua_json_depth(data + 32, length - 32)) return 0;
    root = json_loadb((const char *)data + 32, length - 32, JSON_REJECT_DUPLICATES, NULL);
    if (!root) return 0;
    if (!json_is_object(root) || !dahua_json_budget(root, 1, &nodes)) goto done;
    method = json_object_get(root, "method"); params = json_object_get(root, "params");
    if (!json_is_string(method) || strcmp(json_string_value(method), "client.notifyDevInfo") || !json_is_object(params)) goto done;
    info = json_object_get(params, "deviceInfo");
    if (!json_is_object(info) || !dahua_identity(json_object_get(info, "DeviceType")) ||
        !dahua_identity(json_object_get(info, "SerialNo"))) goto done;
    address = json_object_get(info, "IPv4Address");
    if (json_is_object(address)) {
        json_t *ip;
        ip = json_object_get(address, "IPAddress");
        if (json_is_string(ip) && udp_discovery_ipv4((const unsigned char *)json_string_value(ip),
            (unsigned)json_string_length(ip))) has_address = 1;
    }
    mac = json_object_get(root, "mac");
    if (json_is_string(mac) && json_string_length(mac) == 17 &&
        udp_discovery_mac_text((const unsigned char *)json_string_value(mac), 17)) {
        has_address = 1;
    }
    valid = has_address != 0;
done:
    json_decref(root);
    return valid;
}
#endif
