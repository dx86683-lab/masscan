#include "proto-icmp.h"
#include "proto-preprocess.h"
#include "syn-cookie.h"
#include "util-logger.h"
#include "output.h"
#include "masscan-status.h"
#include "massip-port.h"
#include "main-dedup.h"
#include "masscan.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>


/***************************************************************************
 ***************************************************************************/
static int
matches_me(struct Output *out, ipaddress ip, unsigned port)
{
    unsigned i;

    for (i=0; i<8; i++) {
        if (is_myself(&out->src[i], ip, port))
            return 1;
    }
    return 0;
}

/***************************************************************************
 ***************************************************************************/
static int
parse_port_unreachable(const unsigned char *px, unsigned length,
        unsigned *r_ip_me, unsigned *r_ip_them,
        unsigned *r_port_me, unsigned *r_port_them,
        unsigned *r_ip_proto)
{
    unsigned header_length;
    if (length < 24)
        return -1;
    header_length = (px[0] & 0xF) << 2;
    if (header_length < 20 || header_length > length - 4)
        return -1;
    *r_ip_me = (unsigned)px[12]<<24 | px[13]<<16 | px[14]<<8 | px[15];
    *r_ip_them = (unsigned)px[16]<<24 | px[17]<<16 | px[18]<<8 | px[19];
    *r_ip_proto = px[9]; /* TCP=6, UDP=17 */

    px += header_length;

    *r_port_me = px[0]<<8 | px[1];
    *r_port_them = px[2]<<8 | px[3];

    return 0;
}

/***************************************************************************
 * This is where we handle all incoming ICMP packets. Some of these packets
 * will be due to scans we are doing, like pings (echoes). Some will
 * be inadvertent, such as "destination unreachable" messages.
 ***************************************************************************/
int
icmp_selftest(void)
{
    unsigned ip_me, ip_them, port_me, port_them, ip_proto;
    int err;

    /* bug 1: length inflated by 16 (+ instead of - 8 in handle_icmp).
     * 16 bytes must be rejected; the bug would pass 32. */
    static const unsigned char short_blob[] = {
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x01, /* src IP only, dst IP absent */
    };
    err = parse_port_unreachable(short_blob, sizeof(short_blob),
                                 &ip_me, &ip_them, &port_me, &port_them,
                                 &ip_proto);
    if (err != -1) return 1;

    /* bug 2: px advanced before length decremented, using the wrong px[0].
     * src-port high byte 0x06 (nibble=6): wrong order gives length 24-24=0 < 4. */
    static const unsigned char blob[] = {
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc6, 0x33, 0x64, 0x02, /* src = 198.51.100.2 */
        0xc0, 0x00, 0x02, 0x01, /* dst = 192.0.2.1 */
        0x06, 0x40,             /* src port = 1600  */
        0x00, 0x35,             /* dst port = 53    */
    };
    err = parse_port_unreachable(blob, sizeof(blob),
                                 &ip_me, &ip_them, &port_me, &port_them,
                                 &ip_proto);
    if (err != 0)          return 1;
    if (ip_me != 0xc6336402U || ip_them != 0xc0000201U || ip_proto != 17) return 1;
    if (port_me   != 1600) return 1;
    if (port_them != 53)   return 1;
    {
        struct PreprocessedInfo parsed;
        unsigned size;
        memset(&parsed, 0, sizeof(parsed));
        for (size = 0; size < 8; size++) {
            unsigned char *short_icmp = calloc(size ? size : 1, 1);
            if (short_icmp == NULL)
                return 1;
            handle_icmp(NULL, 0, short_icmp, size, &parsed, 0);
            free(short_icmp);
        }
        parsed.transport_offset = sizeof(blob) + 1;
        handle_icmp(NULL, 0, blob, sizeof(blob), &parsed, 0);
    }
    {
        unsigned char echo[11] = {0};
        struct PreprocessedInfo parsed;
        struct Output out;
        uint64_t entropy;
        unsigned cookie = 0;
        int failed;

        memset(&parsed, 0, sizeof(parsed));
        memset(&out, 0, sizeof(out));
        parsed.src_ip.version = parsed.dst_ip.version = 4;
        parsed.src_ip.ipv4 = 0xc0000201U;
        parsed.dst_ip.ipv4 = 0xc6336402U;
        parsed.transport_offset = 3;
        /* Select a high-bit cookie without depending on host byte order. */
        for (entropy = 0; entropy < 256; entropy++) {
            cookie = (unsigned)syn_cookie(parsed.src_ip, Templ_ICMP_echo,
                                          parsed.dst_ip, 0, entropy);
            if (cookie & 0x80000000U)
                break;
        }
        if (entropy == 256)
            return 1;
        echo[7] = (unsigned char)(cookie >> 24);
        echo[8] = (unsigned char)(cookie >> 16);
        echo[9] = (unsigned char)(cookie >> 8);
        echo[10] = (unsigned char)cookie;
        out.fp = tmpfile();
        if (out.fp == NULL)
            return 1;
        out.funcs = &null_output;
        out.format = Output_None;
        out.is_show_open = 1;
        out.rotate.next = LONG_MAX;

        /* A wrong cookie must not consume the valid response's dedup entry. */
        echo[10] ^= 1;
        handle_icmp(&out, 0, echo, sizeof(echo), &parsed, entropy);
        failed = out.counts.icmp.echo != 0;
        echo[10] ^= 1;
        handle_icmp(&out, 0, echo, sizeof(echo), &parsed, entropy);
        failed |= out.counts.icmp.echo != 1;
        fclose(out.fp);
        if (failed)
            return 1;
    }
    {
        unsigned char options[sizeof(blob) + 4] = {0};
        unsigned char malformed[sizeof(blob)];
        unsigned ihl;
        memcpy(options, blob, 20);
        memcpy(options + 24, blob + 20, 4);
        options[0] = 0x46;
        options[3] = 0x20;
        if (parse_port_unreachable(options, sizeof(options),
                                   &ip_me, &ip_them, &port_me, &port_them,
                                   &ip_proto) != 0 || port_me != 1600 || port_them != 53)
            return 1;
        for (ihl = 0; ihl < 16; ihl++) {
            if (ihl == 5)
                continue;
            memcpy(malformed, blob, sizeof(blob));
            malformed[0] = (unsigned char)(0x40 | ihl);
            if (parse_port_unreachable(malformed, sizeof(malformed),
                                      &ip_me, &ip_them, &port_me, &port_them,
                                      &ip_proto) != -1)
                return 1;
        }
    }
    return 0;
}

void
handle_icmp(struct Output *out, time_t timestamp,
            const unsigned char *px, unsigned length,
            struct PreprocessedInfo *parsed,
            uint64_t entropy)
{
    unsigned type = parsed->port_src;
    unsigned code = parsed->port_dst;
    unsigned seqno_me;
    ipaddress ip_me = parsed->dst_ip;
    ipaddress ip_them = parsed->src_ip;
    unsigned cookie;

    /* dedup ICMP echo replies as well as SYN/ACK replies */
    static struct DedupTable *echo_reply_dedup = NULL;

    if (parsed->transport_offset > length ||
        length - parsed->transport_offset < 8)
        return;

    if (!echo_reply_dedup)
        echo_reply_dedup = dedup_create();

    seqno_me = (unsigned)px[parsed->transport_offset+4]<<24
                | px[parsed->transport_offset+5]<<16
                | px[parsed->transport_offset+6]<<8
                | px[parsed->transport_offset+7]<<0;

    switch (type) {
    case 0: /* ICMP echo reply */
    case 129:
        cookie = (unsigned)syn_cookie(ip_them, Templ_ICMP_echo, ip_me, 0, entropy);
        if ((cookie & 0xFFFFFFFF) != seqno_me)
            return; /* not my response */

        if (dedup_is_duplicate(echo_reply_dedup, ip_them, 0, ip_me, 0))
            break;

        //if (syn_hash(ip_them, Templ_ICMP_echo) != seqno_me)
        //    return; /* not my response */

        /*
         * Report "open" or "existence" of host
         */
        output_report_status(
                            out,
                            timestamp,
                            PortStatus_Open,
                            ip_them,
                            1, /* ip proto */
                            0,
                            0,
                            parsed->ip_ttl,
                            parsed->mac_src);
        break;
    case 3: /* destination unreachable */
        switch (code) {
        case 0: /* net unreachable */
            /* We get these a lot while port scanning, often a flood coming
             * back from broken/misconfigured networks */
            break;
        case 1: /* host unreachable */
            /* This means the router doesn't exist */
            break;
        case 2: /* protocol unreachable */
            /* The host exists, but it doesn't support SCTP */
            break;
        case 3: /* port unreachable */
            if (length - parsed->transport_offset > 8) {
                ipaddress ip_me2;
                ipaddress ip_them2;
                unsigned port_me2, port_them2;
                unsigned ip_proto;
                int err;

                ip_me2.version = 4;
                ip_them2.version = 4;

                err = parse_port_unreachable(
                    px + parsed->transport_offset + 8,
                    length - parsed->transport_offset - 8,
                    &ip_me2.ipv4, &ip_them2.ipv4, &port_me2, &port_them2,
                    &ip_proto);

                if (err)
                    return;

                if (!matches_me(out, ip_me2, port_me2))
                    return;

                switch (ip_proto) {
                case 6:
                    output_report_status(
                                        out,
                                        timestamp,
                                        PortStatus_Closed,
                                        ip_them2,
                                        ip_proto,
                                        port_them2,
                                        0,
                                        parsed->ip_ttl,
                                        parsed->mac_src);
                    break;
                case 17:
                    output_report_status(
                                        out,
                                        timestamp,
                                        PortStatus_Closed,
                                        ip_them2,
                                        ip_proto,
                                        port_them2,
                                        0,
                                        parsed->ip_ttl,
                                        parsed->mac_src);
                    break;
                case 132:
                    output_report_status(
                                        out,
                                        timestamp,
                                        PortStatus_Closed,
                                        ip_them2,
                                        ip_proto,
                                        port_them2,
                                        0,
                                        parsed->ip_ttl,
                                        parsed->mac_src);
                    break;
                }
            }

        }
        break;
    default:
    ;
    }

}
