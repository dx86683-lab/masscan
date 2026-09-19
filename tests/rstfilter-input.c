/* Inspect real RST-filter hash inputs, then forward to the real SipHash. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "misc-rstfilter.h"
#include "crypto-siphash24.h"

static uint64_t captured[2][5];
static uint64_t hashes[2];
static unsigned hash_calls;
static unsigned bad_length;

uint64_t
__real_siphash24(const void *input, size_t length, const uint64_t key[2]);

uint64_t
__wrap_siphash24(const void *input, size_t length, const uint64_t key[2])
{
    uint64_t hash;
    if (length != sizeof(captured[0]))
        bad_length = 1;
    else if (hash_calls < 2)
        memcpy(captured[hash_calls], input, length);
    hash = __real_siphash24(input, length, key);
    if (hash_calls < 2)
        hashes[hash_calls] = hash;
    hash_calls++;
    return hash;
}

static int
check_family(ipaddress src, ipaddress dst, const uint64_t expected[5])
{
    struct ResetFilter *rf = rstfilter_create(UINT64_C(0x123456789abcdef0), 64);
    unsigned i;
    int failed = 0;
    for (i = 0; i < 4; i++) {
        uint64_t decay[5];
        hash_calls = 0;
        bad_length = 0;
        memset(captured, 0, sizeof(captured));
        rstfilter_is_filter(rf, src, 2, dst, 4);
        if (hash_calls != 2 || bad_length) {
            fprintf(stderr, "rstfilter: expected two 40-byte hash inputs\n");
            failed = 1;
            break;
        }
        memcpy(decay, expected, sizeof(decay));
        decay[0] = (unsigned)hashes[0];
        decay[1] = i;
        if (memcmp(captured[0], expected, sizeof(captured[0]))) {
            fprintf(stderr, "rstfilter: IPv%u lookup input differs on call %u (tail=%016llx)\n",
                    src.version, i, (unsigned long long)captured[0][4]);
            failed = 1;
        }
        if (memcmp(captured[1], decay, sizeof(captured[1]))) {
            fprintf(stderr, "rstfilter: IPv%u decay input differs on call %u (tail=%016llx)\n",
                    src.version, i, (unsigned long long)captured[1][4]);
            failed = 1;
        }
    }
    rstfilter_destroy(rf);
    return failed;
}

int
main(void)
{
    ipaddress src = {0}, dst = {0};
    static const uint64_t ipv4_input[5] = {1, 2, 3, 4, 0};
    static const uint64_t ipv6_input[5] = {1, 2, 3, 4, 0x00020004};
    int failed;

    src.version = dst.version = 4;
    src.ipv4 = 1;
    dst.ipv4 = 3;
    failed = check_family(src, dst, ipv4_input);

    src.version = dst.version = 6;
    src.ipv6.hi = 1;
    src.ipv6.lo = 2;
    dst.ipv6.hi = 3;
    dst.ipv6.lo = 4;
    failed |= check_family(src, dst, ipv6_input);
    if (!failed)
        puts("rstfilter hash input regression: success!");
    return failed;
}
