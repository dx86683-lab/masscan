#include "proto-udp-tftp.h"
#ifdef UDP_EXTENDED_PROBES
#include "proto-udp-runtime.h"
#include <openssl/crypto.h>
#include <string.h>

struct TftpPending {
    struct UdpProbeTarget target;
    uint64_t cookie;
    time_t started;
};

static struct TftpPending pending[256];
static CRYPTO_ONCE pending_once = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_RWLOCK *pending_lock;

static void
tftp_init_lock(void)
{
    pending_lock = CRYPTO_THREAD_lock_new();
}

static int
tftp_target_equal(const struct UdpProbeTarget *a, const struct UdpProbeTarget *b)
{
    return a->source_port == b->source_port && ipaddress_is_equal(a->source, b->source) &&
        ipaddress_is_equal(a->destination, b->destination);
}

int
tftp_probe_prepare(uint64_t cookie, const struct UdpProbeTarget *target,
                     struct UdpPreparedProbe *result)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char id[32];
    unsigned i, slot = 256;
    time_t now = time(NULL);
    if (now <= 0 || !target || !target->source_port ||
        !udp_probe_derive_target("tftp-filename", cookie, 69, target, id) ||
        !CRYPTO_THREAD_run_once(&pending_once, tftp_init_lock) || !pending_lock ||
        !CRYPTO_THREAD_write_lock(pending_lock)) return 0;
    for (i = 0; i < 256; i++) {
        if (pending[i].started && tftp_target_equal(&pending[i].target, target)) { slot = i; break; }
        if (!pending[i].started || now < pending[i].started || now - pending[i].started > 60) slot = i;
    }
    if (slot != 256) {
        pending[slot].target = *target;
        pending[slot].cookie = cookie;
        pending[slot].started = now;
    }
    CRYPTO_THREAD_unlock(pending_lock);
    if (slot == 256) return 0;
    memcpy(result->payload, "\x00\x01" "probe-", 8);
    for (i = 0; i < 16; i++) {
        result->payload[8 + 2 * i] = hex[id[i] >> 4];
        result->payload[9 + 2 * i] = hex[id[i] & 15];
    }
    memcpy(result->payload + 40, ".missing\x00" "octet", 15);
    result->length = 55;
    return 1;
}

int
tftp_probe_response(const unsigned char *data, unsigned length, uint64_t cookie,
                      const struct UdpProbeTarget *target, time_t timestamp)
{
    unsigned i;
    int matched = 0;
    if (!target || length < 5 || length > 516 || data[0] || data[1] != 5 ||
        data[2] || data[3] > 7 || data[length - 1]) return 0;
    for (i = 4; i < length - 1; i++) if (data[i] < 32 || data[i] > 126) return 0;
    if (!CRYPTO_THREAD_run_once(&pending_once, tftp_init_lock) || !pending_lock ||
        !CRYPTO_THREAD_read_lock(pending_lock)) return 0;
    for (i = 0; i < 256; i++) {
        if (pending[i].started && timestamp >= pending[i].started && timestamp - pending[i].started <= 60 &&
            pending[i].cookie == cookie && tftp_target_equal(&pending[i].target, target)) { matched = 1; break; }
    }
    CRYPTO_THREAD_unlock(pending_lock);
    return matched;
}

int
tftp_probe_classify(const unsigned char *data, unsigned length, uint64_t cookie,
                      const struct UdpProbeTarget *target)
{
    return tftp_probe_response(data, length, cookie, target, time(NULL));
}
#endif
