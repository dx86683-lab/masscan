#include "proto-udp.h"
#include "proto-udp-probe.h"
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


    if (out->masscan != NULL && out->masscan->is_udp_probe_experimental) {
        uint64_t cookie = syn_cookie(ip_them, port_them | Templ_UDP,
                                     parsed->dst_ip, parsed->port_dst,
                                     entropy);
        probe_protocol = udp_probe_classify(port_them,
                                            px + parsed->app_offset,
                                            parsed->app_length, cookie);
    }

    if (probe_protocol != PROTO_NONE) {
        output_report_banner(out, timestamp, ip_them, 17, port_them,
                             probe_protocol, parsed->ip_ttl,
                             px + parsed->app_offset, parsed->app_length);
        status = 1;
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
    unsigned banner_count;
    unsigned banner_length;
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
    if (!udp_probe_prepare(80, cookie, &request))
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

    return 0;
}
