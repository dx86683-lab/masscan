#include "proto-udp.h"
#include "proto-udp-probe.h"
#include "proto-udp-runtime.h"
#include "proto-coap.h"
#include "proto-dns.h"
#include "proto-isakmp.h"
#include "proto-netbios.h"
#include "proto-snmp.h"
#include "proto-memcached.h"
#include "proto-ntp.h"
#include "proto-zeroaccess.h"
#include "proto-preprocess.h"
#include "syn-cookie.h"
#include "util-logger.h"
#include "output.h"
#include "masscan-status.h"
#include "unusedparm.h"
#include "masscan.h"
#include "massip-port.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>


/****************************************************************************
 * When the "--banner" command-line option is selected, this will
 * will take up to 64 bytes of a response and display it. Other UDP
 * protocol parsers may also default to this function when they detect
 * a response is not the protocol they expect. For example, if a response
 * to port 161 obviously isn't ASN.1 formatted, the SNMP parser will
 * call this function instead. In such cases, the protocool identifier will
 * be [unknown] rather than [snmp].
 ****************************************************************************/
unsigned
default_udp_parse(struct Output *out, time_t timestamp,
           const unsigned char *px, unsigned length,
           struct PreprocessedInfo *parsed,
           uint64_t entropy)
{
    ipaddress ip_them = parsed->src_ip;
    unsigned port_them = parsed->port_src;
    
    UNUSEDPARM(entropy);


    if (length > 64)
        length = 64;
    
    output_report_banner(
                         out, timestamp,
                         ip_them, 17, port_them,
                         PROTO_NONE,
                         parsed->ip_ttl,
                         px, length);

    return 1;
}

/****************************************************************************
 ****************************************************************************/
void 
handle_udp(struct Output *out, time_t timestamp,
        const unsigned char *px, unsigned length, 
        struct PreprocessedInfo *parsed, uint64_t entropy)
{
    ipaddress ip_them = parsed->src_ip;
    unsigned port_them = parsed->port_src;
    unsigned status = 0;
    unsigned is_raw = 0;
    enum ApplicationProtocol probe_protocol = PROTO_NONE;
    const unsigned char *banner_data = px + parsed->app_offset;
    unsigned banner_length = parsed->app_length;

    if (out->masscan && out->masscan->is_udp_probe_experimental &&
        udp_probe_is_registered(69) && out->masscan->targets.ports.count == 1 &&
        out->masscan->targets.ports.list[0].begin == (69 | Templ_UDP) &&
        out->masscan->targets.ports.list[0].end == (69 | Templ_UDP)) {
        struct UdpProbeTarget target;
        uint64_t cookie = (uint32_t)syn_cookie(ip_them, 69 | Templ_UDP,
                                              parsed->dst_ip, parsed->port_dst, entropy);
        target.source = parsed->dst_ip; target.destination = ip_them;
        target.source_port = parsed->port_dst;
        if (!port_them) return;
        probe_protocol = udp_probe_classify_timed(69, banner_data, banner_length,
                                                  cookie, &target, timestamp);
        if (probe_protocol == PROTO_NONE) return;
        port_them = 69;
        banner_data = (const unsigned char *)"error-response";
        banner_length = 14;
        is_raw = 1;
    }

    if (out->masscan && out->masscan->is_udp_probe_experimental &&
        (!massip_has_ip(&out->masscan->targets, ip_them) ||
         !massip_has_port(&out->masscan->targets, port_them | Templ_UDP))) return;

    /* Report "open" status regardless  */
    output_report_status(
                             out,
                             timestamp,
                             PortStatus_Open,
                             ip_them,
                             17, /* ip proto = udp */
                             port_them,
                             0,
                             parsed->ip_ttl,
                             parsed->mac_src);


    if (probe_protocol == PROTO_NONE && out->masscan != NULL && out->masscan->is_udp_probe_experimental) {
        uint64_t cookie = (uint32_t)syn_cookie(ip_them, port_them | Templ_UDP,
                                     parsed->dst_ip, parsed->port_dst,
                                     entropy);
        struct UdpProbeTarget target;
        target.source = parsed->dst_ip;
        target.destination = parsed->src_ip;
        target.source_port = parsed->port_dst;
        probe_protocol = udp_probe_classify_target(port_them,
                                            px + parsed->app_offset,
                                            parsed->app_length, cookie, &target);
    }

    if (probe_protocol != PROTO_NONE) {
        if (probe_protocol == PROTO_UBIQUITI || probe_protocol == PROTO_PCANYWHERE ||
            probe_protocol == PROTO_SBUS || probe_protocol == PROTO_LANTRONIX ||
            probe_protocol == PROTO_DB2 || probe_protocol == PROTO_MOXA) {
            banner_data = (const unsigned char *)"discovery-response";
            banner_length = 18;
        }
        output_report_banner(out, timestamp, ip_them, 17, port_them,
                             probe_protocol, parsed->ip_ttl,
                             banner_data, banner_length);
        status = 1;
    } else if (out->masscan != NULL && out->masscan->is_udp_probe_experimental &&
               udp_probe_is_registered(port_them)) {
        /* A rejected experimental reply must not gain a fallback protocol label. */
        status = 0;
    } else switch (port_them) {
        case 53: /* DNS - Domain Name System (amplifier) */
            status = handle_dns(out, timestamp, px, length, parsed, entropy);
            break;
        case 123: /* NTP - Network Time Protocol (amplifier) */
            status = ntp_handle_response(out, timestamp, px, length, parsed, entropy);
            break;
        case 137: /* NetBIOS (amplifier) */
            status = handle_nbtstat(out, timestamp, px, length, parsed, entropy);
            break;
        case 161: /* SNMP - Simple Network Managment Protocol (amplifier) */
            status = handle_snmp(out, timestamp, px, length, parsed, entropy);
            break;
        case 500: /* ISAKMP - IPsec key negotiation */
            status = isakmp_parse(out, timestamp,
                                px + parsed->app_offset, parsed->app_length, parsed, entropy);
            break;
        case 5683:
            status = coap_handle_response(out, timestamp, 
                                px + parsed->app_offset, parsed->app_length, parsed, entropy);
            break;
        case 11211: /* memcached (amplifier) */
            px += parsed->app_offset;
            length = parsed->app_length;
            status = memcached_udp_parse(out, timestamp, px, length, parsed, entropy);
            break;
        case 16464:
        case 16465:
        case 16470:
        case 16471:
            status = handle_zeroaccess(out, timestamp, px, length, parsed, entropy);
            break;
        default:
            px += parsed->app_offset;
            length = parsed->app_length;
            status = default_udp_parse(out, timestamp, px, length, parsed, entropy);
            is_raw = 1;
            break;
    }

    
    /* Report banner if some parser didn't already do so.
     * Also report raw dump if `--rawudp` specified on the
     * command-line, even if a protocol above already created a more detailed
     * banner. */
    if (status == 0 || (out->is_banner_rawudp && !is_raw)) {
            output_report_banner(
                    out,
                    timestamp,
                    ip_them,
                    17, /* ip proto = udp */
                    port_them,
                    PROTO_NONE,
                    parsed->ip_ttl,
                    px + parsed->app_offset,
                    parsed->app_length);
    }
}

struct UdpSelftestCapture {
    unsigned status_count;
    unsigned banner_count;
    unsigned banner_length;
    unsigned port;
    enum ApplicationProtocol protocol;
    unsigned char banner[8];
};

static struct UdpSelftestCapture udp_selftest_capture;

static void
udp_selftest_open(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
}

static void
udp_selftest_close(struct Output *out, FILE *fp)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
}

static void
udp_selftest_status(struct Output *out, FILE *fp, time_t timestamp,
                    int status, ipaddress ip, unsigned ip_proto,
                    unsigned port, unsigned reason, unsigned ttl)
{
    udp_selftest_capture.status_count++;
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
    UNUSEDPARM(timestamp);
    UNUSEDPARM(status);
    UNUSEDPARM(ip);
    UNUSEDPARM(ip_proto);
    UNUSEDPARM(port);
    UNUSEDPARM(reason);
    UNUSEDPARM(ttl);
}

static void
udp_selftest_banner(struct Output *out, FILE *fp, time_t timestamp,
                    ipaddress ip, unsigned ip_proto, unsigned port,
                    enum ApplicationProtocol proto, unsigned ttl,
                    const unsigned char *px, unsigned length)
{
    UNUSEDPARM(out);
    UNUSEDPARM(fp);
    UNUSEDPARM(timestamp);
    UNUSEDPARM(ip);
    UNUSEDPARM(ip_proto);
    UNUSEDPARM(port);
    UNUSEDPARM(ttl);

    udp_selftest_capture.banner_count++;
    udp_selftest_capture.banner_length = length;
    udp_selftest_capture.port = port;
    udp_selftest_capture.protocol = proto;
    if (length > sizeof(udp_selftest_capture.banner))
        length = sizeof(udp_selftest_capture.banner);
    memcpy(udp_selftest_capture.banner, px, length);
}

static const struct OutputType udp_selftest_output = {
    "selftest",
    0,
    udp_selftest_open,
    udp_selftest_close,
    udp_selftest_status,
    udp_selftest_banner
};

int
proto_udp_selftest(void)
{
    static const unsigned char packet[] = {
        0xaa, 0xbb, 0xcc, 0x10, 0x20, 0x30, 0x40, 0x50
    };
    static const unsigned char expected[] = {0x10, 0x20, 0x30};
    static const unsigned char mac[6] = {0};
    struct PreprocessedInfo parsed;
    struct Output out;
    struct Masscan masscan;
    struct UdpPreparedProbe request;
    struct Range planned_ipv4 = {0, 0xffffffff};
    struct Range planned_ports = {Templ_UDP, Templ_UDP + 65535};
    struct Range6 planned_ipv6 = {{0, 0}, {UINT64_MAX, UINT64_MAX}};
    unsigned char response[27];
    uint64_t cookie;
    FILE *fp;

    memset(&parsed, 0, sizeof(parsed));
    memset(&out, 0, sizeof(out));
    memset(&udp_selftest_capture, 0, sizeof(udp_selftest_capture));

    fp = tmpfile();
    if (fp == NULL)
        return 1;

    parsed.src_ip.version = 4;
    parsed.src_ip.ipv4 = 0x7f000001;
    parsed.port_src = 65000;
    parsed.app_offset = 3;
    parsed.app_length = sizeof(expected);
    parsed.ip_ttl = 64;
    parsed.mac_src = mac;

    out.fp = fp;
    out.funcs = &udp_selftest_output;
    out.format = Output_None;
    out.is_banner = 1;
    out.is_show_open = 1;
    out.rotate.next = LONG_MAX;

    handle_udp(&out, 0, packet, sizeof(packet), &parsed, 0);
    fclose(fp);

    if (udp_selftest_capture.banner_count != 1)
        return 1;
    if (udp_selftest_capture.banner_length != sizeof(expected))
        return 1;
    if (memcmp(udp_selftest_capture.banner, expected, sizeof(expected)) != 0)
        return 1;

    memset(&udp_selftest_capture, 0, sizeof(udp_selftest_capture));
    out.is_banner_rawudp = 1;
    fp = tmpfile();
    if (fp == NULL)
        return 1;
    out.fp = fp;
    handle_udp(&out, 0, packet, sizeof(packet), &parsed, 0);
    fclose(fp);
    if (udp_selftest_capture.banner_count != 1)
        return 1;

    memset(&masscan, 0, sizeof(masscan));
    masscan.is_udp_probe_experimental = 1;
    masscan.targets.ipv4.list = &planned_ipv4;
    masscan.targets.ipv4.count = 1;
    masscan.targets.ipv6.list = &planned_ipv6;
    masscan.targets.ipv6.count = 1;
    masscan.targets.ports.list = &planned_ports;
    masscan.targets.ports.count = 1;
    out.masscan = &masscan;
    out.is_banner_rawudp = 0;
    parsed.port_src = 80;
    parsed.port_dst = 40000;
    parsed.dst_ip.version = 4;
    parsed.dst_ip.ipv4 = 0x7f000002;
    parsed.app_offset = 0;
    parsed.app_length = sizeof(response);
    cookie = syn_cookie(parsed.src_ip, parsed.port_src | Templ_UDP,
                        parsed.dst_ip, parsed.port_dst, 7);
    if (!udp_probe_prepare(80, cookie, NULL, &request))
        return 1;
    response[0] = 0xc0;
    memset(response + 1, 0, 4);
    response[5] = 8;
    memcpy(response + 6, request.payload + 15, 8);
    response[14] = 8;
    memcpy(response + 15, request.payload + 6, 8);
    response[23] = 0;
    response[24] = 0;
    response[25] = 0;
    response[26] = 1;
    memset(&udp_selftest_capture, 0, sizeof(udp_selftest_capture));
    fp = tmpfile();
    if (fp == NULL)
        return 1;
    out.fp = fp;
    handle_udp(&out, 0, response, sizeof(response), &parsed, 7);
    fclose(fp);
    if (udp_selftest_capture.banner_count != 1 ||
        udp_selftest_capture.protocol != PROTO_QUIC)
        return 1;

    parsed.port_src = 64738;
    parsed.app_length = 24;
    cookie = syn_cookie(parsed.src_ip, parsed.port_src | Templ_UDP,
                        parsed.dst_ip, parsed.port_dst, 7);
    if (!udp_probe_prepare(64738, (uint32_t)cookie, NULL, &request))
        return 1;
    memset(response, 0, sizeof(response));
    response[1] = 1;
    response[2] = 5;
    memcpy(response + 4, request.payload + 4, 8);
    memset(&udp_selftest_capture, 0, sizeof(udp_selftest_capture));
    fp = tmpfile();
    if (fp == NULL)
        return 1;
    out.fp = fp;
    handle_udp(&out, 0, response, 24, &parsed, 7);
    fclose(fp);
    if (udp_selftest_capture.banner_count != 1 ||
        udp_selftest_capture.protocol != PROTO_MUMBLE)
        return 1;

    response[11] ^= 1;
    memset(&udp_selftest_capture, 0, sizeof(udp_selftest_capture));
    fp = tmpfile();
    if (fp == NULL)
        return 1;
    out.fp = fp;
    handle_udp(&out, 0, response, 24, &parsed, 7);
    fclose(fp);
    if (udp_selftest_capture.protocol == PROTO_MUMBLE)
        return 1;

    parsed.port_src = 123;
    parsed.app_length = 4;
    memset(response, 0, sizeof(response));
    response[0] = 0x97;
    memset(&udp_selftest_capture, 0, sizeof(udp_selftest_capture));
    fp = tmpfile();
    if (fp == NULL) return 1;
    out.fp = fp;
    handle_udp(&out, 0, response, 4, &parsed, 7);
    fclose(fp);
    if (udp_selftest_capture.banner_count != 1 ||
        udp_selftest_capture.protocol != PROTO_NONE) return 1;

    {
        unsigned char discovery[72] = {0};
        unsigned variant;
        memcpy(discovery, "\x06\x10\x02\x0c\x00\x48\x08\x01\xc0\x00\x02\x01\x0e\x57", 14);
        discovery[14] = 54; discovery[15] = 1; discovery[16] = 2;
        memcpy(discovery + 68, "\x04\x02\x02\x02", 4);
        for (variant = 0; variant < 3; variant++) {
            planned_ipv4.begin = planned_ipv4.end = 0xc6336401;
            planned_ports.begin = planned_ports.end = Templ_UDP + (variant == 1 ? 123 : 3671);
            parsed.src_ip.ipv4 = variant == 0 ? 0xc6336402 : 0xc6336401;
            parsed.port_src = 3671; parsed.app_offset = 0; parsed.app_length = sizeof(discovery);
            memset(&udp_selftest_capture, 0, sizeof(udp_selftest_capture));
            fp = tmpfile();
            if (!fp) return 1;
            out.fp = fp;
            handle_udp(&out, 0, discovery, sizeof(discovery), &parsed, 7);
            fclose(fp);
            if (variant < 2 && (udp_selftest_capture.banner_count || udp_selftest_capture.status_count)) {
                fprintf(stderr, "udp: unplanned endpoint reported\n");
                return 1;
            }
            if (variant == 2 && (udp_selftest_capture.protocol != PROTO_KNX ||
                udp_selftest_capture.banner_count != 1 || udp_selftest_capture.status_count != 1)) return 1;
        }
        planned_ipv4.begin = 0; planned_ipv4.end = 0xffffffff;
        planned_ports.begin = Templ_UDP; planned_ports.end = Templ_UDP + 65535;
    }
    {
        static const unsigned char discovery[] =
            "\x01\x00\x00\x13\x01\x00\x06\x02\x00\x00\x00\x00\x01\x14\x00\x07" "TestBox";
        parsed.port_src = 10001; parsed.app_length = sizeof(discovery) - 1;
        memset(&udp_selftest_capture, 0, sizeof(udp_selftest_capture));
        fp = tmpfile();
        if (!fp) return 1;
        out.fp = fp;
        handle_udp(&out, 0, discovery, sizeof(discovery) - 1, &parsed, 7);
        fclose(fp);
        if (udp_selftest_capture.protocol != PROTO_UBIQUITI ||
            udp_selftest_capture.banner_count != 1 || udp_selftest_capture.banner_length != 18) {
            fprintf(stderr, "ubiquiti: discovery summary not emitted\n"); return 1;
        }
        parsed.port_src = 5632; parsed.app_length = 17;
        memset(&udp_selftest_capture, 0, sizeof(udp_selftest_capture));
        fp = tmpfile();
        if (!fp) return 1;
        out.fp = fp;
        handle_udp(&out, 0, (const unsigned char *)"NRLAB___AHM_3___", 17, &parsed, 7);
        fclose(fp);
        if (udp_selftest_capture.protocol != PROTO_PCANYWHERE ||
            udp_selftest_capture.banner_count != 1 || udp_selftest_capture.banner_length != 18) return 1;
    }
    {
        static const struct {
            unsigned port, length;
            enum ApplicationProtocol protocol;
            const char *reply;
        } fixtures[] = {
            {30718, 30, PROTO_LANTRONIX,
                "\x00\x00\x00\xf7\x00\x00\x00\x00\x33\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x20\x4a\x12\x34\x56"},
            {523, 27, PROTO_DB2, "DB2RETADDR\x00" "SQL09070\x00" "dbhost\x00"},
            {4800, 24, PROTO_MOXA,
                "\x81\x00\x00\x18\x00\x00\x00\x00\x00\x60\x00\x80\x50\x62\x00\x90\xe8\x00\x00\x01\xc0\x00\x02\x01"},
            {5050, 12, PROTO_SBUS, "\x00\x00\x00\x0c\x00\x00\x00\x00\x01\x07\x00\x00"}
        };
        unsigned f;
        for (f = 0; f < sizeof(fixtures) / sizeof(*fixtures); f++) {
            unsigned char packet[64];
            memcpy(packet, fixtures[f].reply, fixtures[f].length);
            parsed.port_src = fixtures[f].port; parsed.app_length = fixtures[f].length;
            if (parsed.port_src == 5050) {
                unsigned crc = 0, i, b;
                cookie = syn_cookie(parsed.src_ip, 5050 | Templ_UDP,
                                    parsed.dst_ip, parsed.port_dst, 7);
                packet[6] = (unsigned char)(cookie >> 8); packet[7] = (unsigned char)cookie;
                for (i = 0; i < 10; i++) {
                    crc ^= (unsigned)packet[i] << 8;
                    for (b = 0; b < 8; b++) crc = ((crc << 1) ^ ((crc & 0x8000) ? 0x1021 : 0)) & 0xffff;
                }
                packet[10] = (unsigned char)(crc >> 8); packet[11] = (unsigned char)crc;
            }
            memset(&udp_selftest_capture, 0, sizeof(udp_selftest_capture));
            fp = tmpfile();
            if (!fp) return 1;
            out.fp = fp;
            handle_udp(&out, 0, packet, fixtures[f].length, &parsed, 7);
            fclose(fp);
            if (udp_selftest_capture.protocol != fixtures[f].protocol ||
                udp_selftest_capture.banner_count != 1 || udp_selftest_capture.banner_length != 18) return 1;
        }
    }
#ifdef UDP_EXTENDED_PROBES
    parsed.port_src = 1194;
    parsed.app_length = 26;
    cookie = syn_cookie(parsed.src_ip, parsed.port_src | Templ_UDP,
                        parsed.dst_ip, parsed.port_dst, 7);
    if (!(cookie >> 32) || !udp_probe_runtime_init() ||
        !udp_probe_prepare(1194, (uint32_t)cookie, NULL, &request)) return 1;
    memset(response, 0, sizeof(response));
    response[0] = 0x40; response[1] = 1; response[9] = 1;
    memcpy(response + 14, request.payload + 1, 8);
    memset(&udp_selftest_capture, 0, sizeof(udp_selftest_capture));
    fp = tmpfile();
    if (fp == NULL) return 1;
    out.fp = fp;
    handle_udp(&out, 0, response, 26, &parsed, 7);
    fclose(fp);
    if (udp_selftest_capture.banner_count != 1 ||
        udp_selftest_capture.protocol != PROTO_OPENVPN) {
        fprintf(stderr, "udp: prepared cookie failed receive correlation\n");
        return 1;
    }
    {
        unsigned family;
        unsigned char binding[32];
        struct UdpProbeTarget target;
        for (family = 4; family <= 6; family += 2) {
            parsed.src_ip.version = parsed.dst_ip.version = family;
            if (family == 6) {
                parsed.src_ip.ipv6.hi = parsed.dst_ip.ipv6.hi = UINT64_C(0x20010db800000000);
                parsed.src_ip.ipv6.lo = 1; parsed.dst_ip.ipv6.lo = 2;
            }
            parsed.port_src = 3478;
            parsed.app_length = sizeof(binding);
            target.source = parsed.dst_ip;
            target.destination = parsed.src_ip;
            target.source_port = parsed.port_dst;
            cookie = syn_cookie(parsed.src_ip, parsed.port_src | Templ_UDP,
                                parsed.dst_ip, parsed.port_dst, 7);
            if (!udp_probe_prepare(3478, (uint32_t)cookie, &target, &request)) return 1;
            memcpy(binding, request.payload, 20);
            binding[0] = 1; binding[3] = 12;
            memcpy(binding + 20, "\x00\x20\x00\x08\x00\x01\xa1\x47\xe1\x12\xa6\x43", 12);
            memset(&udp_selftest_capture, 0, sizeof(udp_selftest_capture));
            fp = tmpfile();
            if (fp == NULL) return 1;
            out.fp = fp;
            handle_udp(&out, 0, binding, sizeof(binding), &parsed, 7);
            fclose(fp);
            if (udp_selftest_capture.banner_count != 1 ||
                udp_selftest_capture.protocol != PROTO_STUN) return 1;
        }
    }
    {
        struct UdpProbeTarget target;
        struct Range single_port = {Templ_UDP + 69, Templ_UDP + 69};
        static const unsigned char error_reply[] = {0, 5, 0, 1, 'E', 0};
        parsed.src_ip.version = parsed.dst_ip.version = 4;
        parsed.src_ip.ipv4 = 0xc6336401; parsed.dst_ip.ipv4 = 0xc0000201;
        parsed.port_src = 55000; parsed.port_dst = 40000;
        parsed.app_offset = 0; parsed.app_length = sizeof(error_reply);
        target.source = parsed.dst_ip; target.destination = parsed.src_ip;
        target.source_port = parsed.port_dst;
        masscan.targets.ports.list = &single_port;
        masscan.targets.ports.count = 1;
        cookie = (uint32_t)syn_cookie(parsed.src_ip, 69 | Templ_UDP,
                                      parsed.dst_ip, parsed.port_dst, 7);
        if (!udp_probe_prepare(69, cookie, &target, &request)) return 1;
        memset(&udp_selftest_capture, 0, sizeof(udp_selftest_capture));
        fp = tmpfile();
        if (!fp) return 1;
        out.fp = fp;
        handle_udp(&out, time(NULL), error_reply, sizeof(error_reply), &parsed, 7);
        fclose(fp);
        if (udp_selftest_capture.banner_count != 1 ||
            udp_selftest_capture.protocol != PROTO_TFTP_ERROR || udp_selftest_capture.port != 69 ||
            udp_selftest_capture.banner_length != 14) return 1;
        {
            unsigned j;
            unsigned char changed[7];
            time_t now = time(NULL);
            if (request.length != 55 || memcmp(request.payload, "\x00\x01" "probe-", 8) ||
                memcmp(request.payload + 40, ".missing\x00" "octet", 15)) return 1;
            for (j = 8; j < 40; j++)
                if (!strchr("0123456789abcdef", request.payload[j])) return 1;
            for (j = 0; j < sizeof(error_reply); j++)
                if (udp_probe_classify_target(69, error_reply, j, cookie, &target) != PROTO_NONE) return 1;
            if (udp_probe_classify_target(69, error_reply, sizeof(error_reply), cookie, &target) != PROTO_TFTP_ERROR ||
                udp_probe_classify_target(69, error_reply, sizeof(error_reply), cookie + 1, &target) != PROTO_NONE ||
                udp_probe_classify(69, error_reply, sizeof(error_reply), cookie) != PROTO_NONE) return 1;
            for (j = 0; j < 10; j++) {
                time_t received = now;
                memcpy(changed, error_reply, sizeof(error_reply));
                parsed.src_ip = target.destination; parsed.dst_ip = target.source;
                parsed.port_src = 55000; parsed.port_dst = target.source_port;
                parsed.app_length = sizeof(error_reply);
                if (j == 0) parsed.src_ip.ipv4++;
                if (j == 1) parsed.dst_ip.ipv4++;
                if (j == 2) parsed.port_dst++;
                if (j == 3) received += 61;
                if (j == 4) received = 0;
                if (j == 5) changed[1] = 3;
                if (j == 6) changed[3] = 8;
                if (j == 7) changed[5] = 'X';
                if (j == 8) { changed[6] = 0; parsed.app_length = 7; }
                if (j == 9) parsed.port_src = 0;
                memset(&udp_selftest_capture, 0, sizeof(udp_selftest_capture));
                fp = tmpfile();
                if (!fp) return 1;
                out.fp = fp;
                handle_udp(&out, received, changed, parsed.app_length, &parsed, 7);
                fclose(fp);
                if (udp_selftest_capture.banner_count) return 1;
            }
        }
    }
#endif

    return 0;
}
