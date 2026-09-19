#include "util-extract.h"


unsigned char
e_next_byte(struct ebuf_t *ebuf) {
    if (ebuf->offset + 1 > ebuf->max)
        return -1;
    
    return ebuf->buf[ebuf->offset++];
}

unsigned short
e_next_short16(struct ebuf_t *ebuf, int endian) {
    const unsigned char *buf = ebuf->buf;
    size_t offset = ebuf->offset;
    unsigned short result;
    
    if (ebuf->offset + 2 > ebuf->max)
        return -1;

    if (endian == EBUF_BE) {
        result = buf[offset+0]<<8 | buf[offset+1];
    } else {
        result = buf[offset+1]<<8 | buf[offset+0];
    }
    ebuf->offset += 2;
    return result;
}
unsigned e_next_int32(struct ebuf_t *ebuf, int endian) {
    const unsigned char *buf = ebuf->buf;
    size_t offset = ebuf->offset;
    unsigned result;
    
    if (ebuf->offset + 4 > ebuf->max)
        return -1;

    if (endian == EBUF_BE) {
        result = (unsigned)buf[offset+0]<<24 | buf[offset+1] << 16
                    | buf[offset+2]<<8 | buf[offset+3] << 0;
    } else {
        result = (unsigned)buf[offset+3]<<24 | buf[offset+2] << 16
                    | buf[offset+1]<<8 | buf[offset+0] << 0;
    }
    ebuf->offset += 4;
    return result;
}
unsigned long long
e_next_long64(struct ebuf_t *ebuf, int endian) {
    const unsigned char *buf = ebuf->buf;
    size_t offset = ebuf->offset;
    unsigned long long hi;
    unsigned long long lo;
    
    if (ebuf->offset + 8 > ebuf->max)
        return -1ll;

    if (endian == EBUF_BE) {
        hi = (unsigned long long)buf[offset+0]<<24 | buf[offset+1] << 16
                    | buf[offset+2]<<8 | buf[offset+3] << 0;
        lo = (unsigned long long)buf[offset+4]<<24 | buf[offset+5] << 16
                    | buf[offset+6]<<8 | buf[offset+7] << 0;
    } else {
        lo = (unsigned long long)buf[offset+3]<<24 | buf[offset+2] << 16
                    | buf[offset+1]<<8 | buf[offset+0] << 0;
        hi = (unsigned long long)buf[offset+7]<<24 | buf[offset+6] << 16
                    | buf[offset+5]<<8 | buf[offset+4] << 0;
    }
    ebuf->offset += 8;
    return hi<<32ull | lo;

}


int
e_extract_selftest(void)
{
    static const struct {
        unsigned char be[4];
        unsigned char le[4];
        unsigned expected;
    } cases32[] = {
        {{0x00, 0x00, 0x00, 0x00}, {0x00, 0x00, 0x00, 0x00}, 0},
        {{0x12, 0x34, 0x56, 0x78}, {0x78, 0x56, 0x34, 0x12}, 0x12345678U},
        {{0x80, 0x00, 0x00, 0x00}, {0x00, 0x00, 0x00, 0x80}, 0x80000000U},
        {{0xc1, 0xa2, 0x93, 0x84}, {0x84, 0x93, 0xa2, 0xc1}, 0xc1a29384U},
        {{0xff, 0xff, 0xff, 0xff}, {0xff, 0xff, 0xff, 0xff}, 0xffffffffU}
    };
    static const struct {
        unsigned char be[8];
        unsigned char le[8];
        unsigned long long expected;
    } cases64[] = {
        {{0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}, 0},
        {{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
         {0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12},
         0x123456789abcdef0ULL},
        {{0x80, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0x80},
         0x8000000000000000ULL},
        {{0, 0, 0, 0, 0x80, 0, 0, 0}, {0, 0, 0, 0x80, 0, 0, 0, 0},
         0x0000000080000000ULL},
        {{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88},
         {0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
         0xffeeddccbbaa9988ULL},
        {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
         {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
         0xffffffffffffffffULL}
    };
    unsigned char buffer[9];
    struct ebuf_t ebuf;
    unsigned endian;
    unsigned i;
    unsigned j;
    int failures = 0;

    /* Use a nonzero offset to check advancement and truncated reads. */
    buffer[0] = 0x5a;
    ebuf.buf = buffer;
    for (endian = EBUF_BE; endian <= EBUG_LE; endian++) {
        for (i = 0; i < sizeof(cases32) / sizeof(cases32[0]); i++) {
            for (j = 0; j < 4; j++)
                buffer[j + 1] = endian == EBUF_BE ? cases32[i].be[j] : cases32[i].le[j];
            ebuf.offset = 1;
            ebuf.max = 5;
            if (e_next_int32(&ebuf, endian) != cases32[i].expected || ebuf.offset != 5) {
                fprintf(stderr, "extract 32-bit case %u endian %u failed\n", i, endian);
                failures++;
            }
        }
        for (i = 0; i < sizeof(cases64) / sizeof(cases64[0]); i++) {
            for (j = 0; j < 8; j++)
                buffer[j + 1] = endian == EBUF_BE ? cases64[i].be[j] : cases64[i].le[j];
            ebuf.offset = 1;
            ebuf.max = 9;
            if (e_next_long64(&ebuf, endian) != cases64[i].expected || ebuf.offset != 9) {
                fprintf(stderr, "extract 64-bit case %u endian %u failed\n", i, endian);
                failures++;
            }
        }
        for (i = 0; i < 8; i++) {
            ebuf.max = 1 + i;
            ebuf.offset = 1;
            if (e_next_long64(&ebuf, endian) != 0xffffffffffffffffULL || ebuf.offset != 1) {
                fprintf(stderr, "extract truncated 64-bit endian %u length %u failed\n", endian, i);
                failures++;
            }
            if (i < 4) {
                ebuf.offset = 1;
                if (e_next_int32(&ebuf, endian) != 0xffffffffU || ebuf.offset != 1) {
                    fprintf(stderr, "extract truncated 32-bit endian %u length %u failed\n", endian, i);
                    failures++;
                }
            }
        }
    }
    return failures;
}
