/* Exercise the real receive loop with an in-memory packet input. */
#define main masscan_cli_main
#define rawsock_recv_packet receive_test_packet
#include "../src/main.c"
#undef rawsock_recv_packet
#undef main

static unsigned char *frames[4];
/* The final SCTP header is too short for TCP flags: keep its allocation exact. */
static const unsigned frame_lengths[] = {50, 50, 54, 46};
static unsigned frame_index;

int
receive_test_packet(struct Adapter *adapter, unsigned *length,
                    unsigned *secs, unsigned *usecs,
                    const unsigned char **packet)
{
    (void)adapter;
    if (frame_index == 4) {
        is_rx_done = 1;
        return 1;
    }
    *packet = frames[frame_index];
    *length = frame_lengths[frame_index++];
    *secs = 0x81234567U;
    *usecs = 5678;
    return 0;
}

int
main(int argc, char **argv)
{
    struct Masscan masscan = {0};
    struct ThreadPair pair = {0};
    struct stack_t stack = {0};
    struct Adapter adapter = {0};
    struct PcapFile *capture;
    FILE *trace;
    unsigned char captured[64];
    char trace_text[2048];
    unsigned i, secs, usecs, original, length;
    size_t text_length;

    if (argc != 3 || freopen(argv[2], "w", stdout) == NULL)
        return 2;
    for (i = 0; i < 4; i++) {
        unsigned char *px;
        frames[i] = calloc(frame_lengths[i], 1);
        if (frames[i] == NULL)
            return 2;
        px = frames[i];
        unsigned port = i == 1 ? 40001 : 40000;
        px[12] = 8;
        px[14] = 0x45;
        px[17] = (unsigned char)(frame_lengths[i] - 14);
        px[22] = 64;
        px[23] = (unsigned char)(i == 2 ? 6 : 132);
        px[26] = 10;
        px[29] = 1;
        px[30] = 10;
        px[33] = 2;
        px[34] = 0x0b;
        px[35] = 0x59; /* port 2905 */
        px[36] = (unsigned char)(port >> 8);
        px[37] = (unsigned char)port;
        if (i == 2)
            px[46] = 0x50;
        else if (frame_lengths[i] >= 50) {
            px[46] = 4; /* HEARTBEAT: no status output is expected. */
            px[49] = 4;
        }
    }

    masscan.nic_count = 1;
    masscan.nic[0].src.ipv4.first = 0x0a000002;
    masscan.nic[0].src.ipv4.last = 0x0a000002;
    masscan.nic[0].src.port.first = 40000;
    masscan.nic[0].src.port.last = 40000;
    masscan.is_noreset = 1;
    masscan.nmap.packet_trace = 1;
    snprintf(masscan.pcap_filename, sizeof(masscan.pcap_filename), "%s", argv[1]);
    stack.src = &masscan.nic[0].src;
    adapter.link_type = 1;
    pair.masscan = &masscan;
    pair.stack = &stack;
    pair.adapter = &adapter;
    receive_thread(&pair);
    fflush(stdout);
    free(pair.total_synacks);
    free(pair.total_tcbs);

    capture = pcapfile_openread(argv[1]);
    if (capture == NULL)
        return 2;
    for (i = 0; i < 3; i++) {
        static const unsigned expected_frames[] = {0, 2, 3};
        unsigned expected = expected_frames[i];
        if (!pcapfile_readframe(capture, &secs, &usecs, &original, &length,
                               captured, sizeof(captured)) ||
            secs != 0x81234567U || usecs != 5678 || original != frame_lengths[expected] ||
            length != frame_lengths[expected] ||
            memcmp(captured, frames[expected], length) != 0) {
            fprintf(stderr, "receive recording: expected matching SCTP and TCP frames\n");
            pcapfile_close(capture);
            return 1;
        }
    }
    if (pcapfile_readframe(capture, &secs, &usecs, &original, &length,
                          captured, sizeof(captured))) {
        fprintf(stderr, "receive recording: unrelated destination port recorded\n");
        pcapfile_close(capture);
        return 1;
    }
    pcapfile_close(capture);
    capture = pcapfile_openappend(argv[1], 1);
    if (capture == NULL)
        return 2;
    pcapfile_close(capture);

    trace = fopen(argv[2], "r");
    if (trace == NULL)
        return 2;
    text_length = fread(trace_text, 1, sizeof(trace_text) - 1, trace);
    trace_text[text_length] = '\0';
    fclose(trace);
    if (strstr(trace_text, "UNK") == NULL || strstr(trace_text, "TCP") == NULL ||
        strstr(trace_text, "]:40001") != NULL) {
        fprintf(stderr, "receive recording: missing protocol trace or unrelated port\n");
        return 1;
    }
    for (i = 0; i < 4; i++)
        free(frames[i]);
    fprintf(stderr, "receive recording regression: success!\n");
    return 0;
}
