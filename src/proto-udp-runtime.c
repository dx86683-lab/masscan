#include "proto-udp-runtime.h"
#ifdef UDP_EXTENDED_PROBES
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string.h>

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
#else
int
udp_probe_runtime_init(void)
{
    return 1;
}
#endif
