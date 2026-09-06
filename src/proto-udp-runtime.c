#include "proto-udp-runtime.h"
#ifdef UDP_EXTENDED_PROBES
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string.h>
#include "proto-udp-probe.h"

static unsigned char process_key[32];
static int initialized;

int
udp_probe_runtime_init(void)
{
    if (initialized) return 1;
    if (RAND_bytes(process_key, sizeof(process_key)) != 1) return 0;
    initialized = 1;
    return 1;
}

int
udp_probe_derive(const char *purpose, uint64_t cookie, unsigned char output[32])
{
    unsigned char input[64];
    unsigned length = (unsigned)strlen(purpose), i, written = 0;
    if (!initialized || length > 55) return 0;
    memcpy(input, purpose, length);
    input[length++] = 0;
    for (i = 0; i < 8; i++) input[length++] = (unsigned char)(cookie >> (56 - i * 8));
    return HMAC(EVP_sha256(), process_key, sizeof(process_key), input, length,
                output, &written) != NULL && written == 32;
}

int
udp_probe_derive_target(const char *purpose, uint64_t cookie, unsigned port,
                         const struct UdpProbeTarget *target, unsigned char output[32])
{
    unsigned char input[128];
    unsigned length = (unsigned)strlen(purpose), i, j, written = 0;
    const ipaddress *addresses[2];
    if (!initialized || length > 55 || !target || port > 65535 || target->source_port > 65535)
        return 0;
    addresses[0] = &target->source;
    addresses[1] = &target->destination;
    memcpy(input, purpose, length);
    input[length++] = 0;
    for (i = 0; i < 8; i++) input[length++] = (unsigned char)(cookie >> (56 - i * 8));
    for (j = 0; j < 2; j++) {
        const ipaddress *address = addresses[j];
        if (address->version != 4 && address->version != 6) return 0;
        input[length++] = (unsigned char)address->version;
        if (address->version == 4) {
            for (i = 0; i < 4; i++) input[length++] = (unsigned char)(address->ipv4 >> (24 - i * 8));
        } else {
            for (i = 0; i < 8; i++) input[length++] = (unsigned char)(address->ipv6.hi >> (56 - i * 8));
            for (i = 0; i < 8; i++) input[length++] = (unsigned char)(address->ipv6.lo >> (56 - i * 8));
        }
    }
    input[length++] = (unsigned char)(target->source_port >> 8);
    input[length++] = (unsigned char)target->source_port;
    input[length++] = (unsigned char)(port >> 8);
    input[length++] = (unsigned char)port;
    return HMAC(EVP_sha256(), process_key, sizeof(process_key), input, length,
                output, &written) != NULL && written == 32;
}
#else
int
udp_probe_runtime_init(void)
{
    return 1;
}
#endif
