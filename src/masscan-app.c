#include "masscan-app.h"
#include "util-safefunc.h"

/******************************************************************************
 * When outputting results, we call this function to print out the type of 
 * banner that we've collected
 ******************************************************************************/
const char *
masscan_app_to_string(enum ApplicationProtocol proto)
{
    static char tmp[64];

    switch (proto) {
    case PROTO_NONE: return "unknown";
    case PROTO_HEUR: return "unknown";
    case PROTO_SSH1: return "ssh";
    case PROTO_SSH2: return "ssh";
    case PROTO_HTTP: return "http";
    case PROTO_FTP: return "ftp";
    case PROTO_DNS_VERSIONBIND: return "dns-ver";
    case PROTO_SNMP: return "snmp";
    case PROTO_NBTSTAT: return "nbtstat";
    case PROTO_SSL3:    return "ssl";
    case PROTO_SMB:     return "smb";
    case PROTO_SMTP:    return "smtp";
    case PROTO_POP3:    return "pop";
    case PROTO_IMAP4:   return "imap";
    case PROTO_UDP_ZEROACCESS: return "zeroaccess";
    case PROTO_X509_CERT: return "X509";
    case PROTO_X509_CACERT: return "X509CA";
    case PROTO_HTML_TITLE: return "title";
    case PROTO_HTML_FULL: return "html";
    case PROTO_NTP:     return "ntp";
    case PROTO_VULN:    return "vuln";
    case PROTO_HEARTBLEED:    return "heartbleed";
    case PROTO_TICKETBLEED:    return "ticketbleed";
    case PROTO_VNC_OLD: return "vnc";
    case PROTO_SAFE:    return "safe";
    case PROTO_MEMCACHED: return "memcached";
    case PROTO_SCRIPTING:      return "scripting";
    case PROTO_VERSIONING:     return "versioning";
    case PROTO_COAP:           return "coap";
    case PROTO_TELNET:         return "telnet";
    case PROTO_RDP:            return "rdp";
    case PROTO_HTTP_SERVER:     return "http.server";
    case PROTO_MC:              return "minecraft";
    case PROTO_VNC_RFB:         return "vnc";
    case PROTO_VNC_INFO:        return "vnc-info";
    case PROTO_ISAKMP:          return "isakmp";
    case PROTO_QUIC:            return "quic";
    case PROTO_BITTORRENT:       return "bittorrent";
    case PROTO_MUMBLE:           return "mumble";
    case PROTO_MGCP:             return "mgcp";
    case PROTO_SIP:              return "sip";
    case PROTO_SLP:              return "slp";
    case PROTO_XDMCP:            return "xdmcp";
    case PROTO_NATPMP:           return "natpmp";
    case PROTO_RPC:              return "rpc";
    case PROTO_GTPU:             return "gtpu";
    case PROTO_RIP:              return "rip";
    case PROTO_IPMI:             return "ipmi";
    case PROTO_AFS:              return "afs";
    case PROTO_GTPC:             return "gtpc";
    case PROTO_IPMSG:            return "ipmsg";
    case PROTO_ENIP:             return "enip";
        
    case PROTO_ERROR:           return "error";
            
    default:
        snprintf(tmp, sizeof(tmp), "(%u)", proto);
        return tmp;
    }
}

/******************************************************************************
 ******************************************************************************/
enum ApplicationProtocol
masscan_string_to_app(const char *str)
{
    const static struct {
        const char *name;
        enum ApplicationProtocol value;
    } list[] = {
        {"ssh1",    PROTO_SSH1},
        {"ssh2",    PROTO_SSH2},
        {"ssh",     PROTO_SSH2},
        {"http",    PROTO_HTTP},
        {"ftp",     PROTO_FTP},
        {"dns-ver", PROTO_DNS_VERSIONBIND},
        {"snmp",    PROTO_SNMP},
        {"nbtstat", PROTO_NBTSTAT},
        {"ssl",     PROTO_SSL3},
        {"smtp",    PROTO_SMTP},
        {"smb",     PROTO_SMB},
        {"pop",     PROTO_POP3},
        {"imap",    PROTO_IMAP4},
        {"x509",    PROTO_X509_CERT},
        {"x509ca",  PROTO_X509_CACERT},
        {"zeroaccess",  PROTO_UDP_ZEROACCESS},
        {"title",       PROTO_HTML_TITLE},
        {"html",        PROTO_HTML_FULL},
        {"ntp",         PROTO_NTP},
        {"vuln",        PROTO_VULN},
        {"heartbleed",  PROTO_HEARTBLEED},
        {"ticketbleed", PROTO_TICKETBLEED},
        {"vnc-old",     PROTO_VNC_OLD},
        {"safe",        PROTO_SAFE},
        {"memcached",   PROTO_MEMCACHED},
        {"scripting",   PROTO_SCRIPTING},
        {"versioning",  PROTO_VERSIONING},
        {"coap",        PROTO_COAP},
        {"telnet",      PROTO_TELNET},
        {"rdp",         PROTO_RDP},
        {"http.server", PROTO_HTTP_SERVER},
        {"minecraft",   PROTO_MC},
        {"vnc",         PROTO_VNC_RFB},
        {"vnc-info",    PROTO_VNC_INFO},
        {"isakmp",      PROTO_ISAKMP},
        {"quic",        PROTO_QUIC},
        {"bittorrent",  PROTO_BITTORRENT},
        {"mumble",      PROTO_MUMBLE},
        {"mgcp",        PROTO_MGCP},
        {"sip",         PROTO_SIP},
        {"slp",         PROTO_SLP},
        {"xdmcp",       PROTO_XDMCP},
        {"natpmp",      PROTO_NATPMP},
        {"rpc",         PROTO_RPC},
        {"gtpu",        PROTO_GTPU},
        {"rip",         PROTO_RIP},
        {"ipmi",        PROTO_IPMI},
        {"afs",         PROTO_AFS},
        {"gtpc",        PROTO_GTPC},
        {"ipmsg",       PROTO_IPMSG},
        {"enip",        PROTO_ENIP},
        {0,0}
    };
    size_t i;

    for (i=0; list[i].name; i++) {
        if (strcmp(str, list[i].name) == 0)
            return list[i].value;
    }
    return 0;
}

int
masscan_app_selftest(void) {
    static const struct {
        unsigned enumid;
        unsigned expected;
    } tests[] = {
        {PROTO_SNMP, 7},
        {PROTO_X509_CERT, 15},
        {PROTO_HTTP_SERVER, 31},
        {PROTO_QUIC, 36},
        {PROTO_BITTORRENT, 37},
        {PROTO_ERROR, 38},
        {PROTO_MUMBLE, 39},
        {PROTO_MGCP, 40},
        {PROTO_SIP, 41},
        {PROTO_SLP, 42},
        {PROTO_XDMCP, 43},
        {PROTO_NATPMP, 44},
        {PROTO_RPC, 45},
        {PROTO_GTPU, 46},
        {PROTO_RIP, 47},
        {PROTO_IPMI, 48},
        {PROTO_AFS, 49},
        {PROTO_GTPC, 50},
        {PROTO_IPMSG, 51},
        {PROTO_ENIP, 52},
        {0,0}
    };
    size_t i;
    
    /* The ENUM contains fixed values in external files,
     * so programmers should only add onto its end, not
     * the middle. This self-test will verify that
     * a programmer hasn't made this mistake.
     */
    for (i=0; tests[i].enumid != 0; i++) {
        unsigned enumid = tests[i].enumid;
        unsigned expected = tests[i].expected;
        
        /* YOU ADDED AN ENUM IN THE MIDDLE INSTEAD ON THE END OF THE LIST */
        if (enumid != expected) {
            fprintf(stderr, "[-] %s:%u fail\n", __FILE__, (unsigned)__LINE__);
            fprintf(stderr, "[-] enum expected=%u, found=%u\n", 30, PROTO_HTTP_SERVER);
            return 1;
        }
    }
    
    if (masscan_string_to_app("mumble") != PROTO_MUMBLE ||
        strcmp(masscan_app_to_string(PROTO_MUMBLE), "mumble") != 0)
        return 1;
    if (masscan_string_to_app("mgcp") != PROTO_MGCP ||
        strcmp(masscan_app_to_string(PROTO_MGCP), "mgcp") != 0)
        return 1;
    if (masscan_string_to_app("sip") != PROTO_SIP ||
        strcmp(masscan_app_to_string(PROTO_SIP), "sip") != 0)
        return 1;
    if (masscan_string_to_app("slp") != PROTO_SLP ||
        strcmp(masscan_app_to_string(PROTO_SLP), "slp") != 0)
        return 1;
    if (masscan_string_to_app("xdmcp") != PROTO_XDMCP ||
        strcmp(masscan_app_to_string(PROTO_XDMCP), "xdmcp") != 0)
        return 1;
    if (masscan_string_to_app("natpmp") != PROTO_NATPMP ||
        strcmp(masscan_app_to_string(PROTO_NATPMP), "natpmp") != 0)
        return 1;
    if (masscan_string_to_app("rpc") != PROTO_RPC ||
        strcmp(masscan_app_to_string(PROTO_RPC), "rpc") != 0)
        return 1;
    if (masscan_string_to_app("gtpu") != PROTO_GTPU ||
        strcmp(masscan_app_to_string(PROTO_GTPU), "gtpu") != 0)
        return 1;
    if (masscan_string_to_app("rip") != PROTO_RIP ||
        strcmp(masscan_app_to_string(PROTO_RIP), "rip") != 0)
        return 1;
    if (masscan_string_to_app("ipmi") != PROTO_IPMI ||
        strcmp(masscan_app_to_string(PROTO_IPMI), "ipmi") != 0)
        return 1;
    if (masscan_string_to_app("afs") != PROTO_AFS ||
        strcmp(masscan_app_to_string(PROTO_AFS), "afs") != 0)
        return 1;
    if (masscan_string_to_app("gtpc") != PROTO_GTPC ||
        strcmp(masscan_app_to_string(PROTO_GTPC), "gtpc") != 0)
        return 1;
    if (masscan_string_to_app("ipmsg") != PROTO_IPMSG ||
        strcmp(masscan_app_to_string(PROTO_IPMSG), "ipmsg") != 0)
        return 1;
    if (masscan_string_to_app("enip") != PROTO_ENIP ||
        strcmp(masscan_app_to_string(PROTO_ENIP), "enip") != 0)
        return 1;
    return 0;
}
