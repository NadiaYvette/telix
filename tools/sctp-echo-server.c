/*
 * SCTP-over-UDP echo server for testing Telix SCTP Phase 2.
 *
 * This is a minimal SCTP responder that listens on UDP port 9899 and
 * implements just enough of RFC 4960 to complete a 4-way handshake
 * and echo DATA chunks back to the sender.
 *
 * No external dependencies — manually handles SCTP protocol.
 *
 * Build:  gcc -O2 -o sctp-echo-server tools/sctp-echo-server.c
 * Run:    ./sctp-echo-server
 *
 * Protocol flow:
 *   Guest sends INIT       → we reply INIT-ACK (with cookie)
 *   Guest sends COOKIE-ECHO → we reply COOKIE-ACK
 *   Guest sends DATA       → we reply SACK + DATA (echo)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include <time.h>

#define UDP_ENCAP_PORT 9899
#define SCTP_ECHO_PORT 7
#define MAX_PKT 1500

/* SCTP chunk types */
#define CHUNK_DATA          0
#define CHUNK_INIT          1
#define CHUNK_INIT_ACK      2
#define CHUNK_SACK          3
#define CHUNK_HEARTBEAT     4
#define CHUNK_HEARTBEAT_ACK 5
#define CHUNK_ABORT         6
#define CHUNK_SHUTDOWN      7
#define CHUNK_SHUTDOWN_ACK  8
#define CHUNK_COOKIE_ECHO   10
#define CHUNK_COOKIE_ACK    11
#define CHUNK_SHUTDOWN_COMPLETE 14

/* CRC-32C (Castagnoli) for SCTP checksum */
static uint32_t crc32c_table[256];

static void crc32c_init(void)
{
    for (int i = 0; i < 256; i++) {
        uint32_t crc = (uint32_t)i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0x82F63B78u;
            else
                crc >>= 1;
        }
        crc32c_table[i] = crc;
    }
}

static uint32_t crc32c(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++)
        crc = crc32c_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

/* Compute SCTP checksum (CRC-32C with checksum field zeroed) */
static uint32_t sctp_checksum(const uint8_t *pkt, size_t len)
{
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = (i >= 8 && i < 12) ? 0 : pkt[i];
        crc = crc32c_table[(crc ^ b) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

static void stamp_checksum(uint8_t *pkt, size_t len)
{
    uint32_t cksum = sctp_checksum(pkt, len);
    pkt[8]  = (cksum) & 0xFF;
    pkt[9]  = (cksum >> 8) & 0xFF;
    pkt[10] = (cksum >> 16) & 0xFF;
    pkt[11] = (cksum >> 24) & 0xFF;
}

static void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static void put32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }
static uint16_t get16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
static uint32_t get32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

/* Server state for one association */
struct assoc {
    int active;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t local_vtag;
    uint32_t remote_vtag;
    uint32_t next_tsn;
    uint32_t rcv_next_tsn;
    uint16_t out_streams;
    uint16_t in_streams;
    uint16_t next_ssn;
    struct sockaddr_in peer_addr;
};

static struct assoc assocs[8];
static int num_assocs = 0;
static uint32_t next_vtag = 0xDEAD0001;

/* Cookie: 16 bytes = local_vtag(4) + remote_vtag(4) + ports(4) + magic(4) */
#define COOKIE_MAGIC 0x5C7BC001u

static struct assoc *find_assoc(uint16_t local_port, uint16_t remote_port,
                                struct sockaddr_in *peer)
{
    for (int i = 0; i < num_assocs; i++) {
        if (assocs[i].active &&
            assocs[i].local_port == local_port &&
            assocs[i].remote_port == remote_port)
            return &assocs[i];
    }
    return NULL;
}

static void handle_init(int fd, const uint8_t *pkt, size_t pkt_len,
                        struct sockaddr_in *peer)
{
    if (pkt_len < 32) return; /* 12 header + 20 INIT chunk minimum */

    uint16_t src_port = get16(pkt + 0);
    uint16_t dst_port = get16(pkt + 2);

    /* Parse INIT chunk at offset 12 */
    uint32_t init_tag    = get32(pkt + 16);
    uint32_t a_rwnd      = get32(pkt + 20);
    uint16_t num_out     = get16(pkt + 24);
    uint16_t num_in      = get16(pkt + 26);
    uint32_t initial_tsn = get32(pkt + 28);

    printf("  INIT from port %u → %u, tag=0x%08x, tsn=%u, streams=%u/%u\n",
           src_port, dst_port, init_tag, initial_tsn, num_out, num_in);

    /* Allocate association (pre-ESTABLISHED, waiting for COOKIE-ECHO) */
    if (num_assocs >= 8) {
        printf("  ERROR: too many associations\n");
        return;
    }
    struct assoc *a = &assocs[num_assocs++];
    a->active = 1;
    a->local_port = dst_port;
    a->remote_port = src_port;
    a->local_vtag = next_vtag++;
    a->remote_vtag = init_tag;
    a->next_tsn = 1;
    a->rcv_next_tsn = initial_tsn;
    a->out_streams = num_in < 4 ? num_in : 4;
    a->in_streams = num_out < 4 ? num_out : 4;
    a->next_ssn = 0;
    a->peer_addr = *peer;

    /* Build INIT-ACK response */
    uint8_t resp[128];
    memset(resp, 0, sizeof(resp));

    /* Common header: src=dst_port, dst=src_port, vtag=init_tag */
    put16(resp + 0, dst_port);
    put16(resp + 2, src_port);
    put32(resp + 4, init_tag);  /* VTag = peer's init tag */
    /* checksum filled later */

    /* INIT-ACK chunk */
    size_t off = 12;
    resp[off] = CHUNK_INIT_ACK;
    resp[off + 1] = 0;
    /* chunk length filled later */
    put32(resp + off + 4, a->local_vtag);   /* Initiate Tag */
    put32(resp + off + 8, 65535);           /* A-RWND */
    put16(resp + off + 12, a->out_streams); /* Number of Outbound Streams */
    put16(resp + off + 14, a->in_streams);  /* Number of Inbound Streams */
    put32(resp + off + 16, a->next_tsn);    /* Initial TSN */

    /* State Cookie parameter (type=0x0007) */
    size_t param_off = off + 20;
    put16(resp + param_off, 7);       /* parameter type = State Cookie */
    put16(resp + param_off + 2, 20);  /* parameter length = 4 + 16 bytes cookie */
    /* Cookie: local_vtag + remote_vtag + (local_port|remote_port) + magic */
    put32(resp + param_off + 4, a->local_vtag);
    put32(resp + param_off + 8, a->remote_vtag);
    put16(resp + param_off + 12, a->local_port);
    put16(resp + param_off + 14, a->remote_port);
    put32(resp + param_off + 16, COOKIE_MAGIC);

    size_t chunk_len = 20 + 20; /* INIT-ACK fixed(20) + cookie param(20) */
    put16(resp + off + 2, chunk_len);
    size_t total = 12 + ((chunk_len + 3) & ~3u);

    stamp_checksum(resp, total);
    sendto(fd, resp, total, 0, (struct sockaddr *)peer, sizeof(*peer));
    printf("  → INIT-ACK sent (tag=0x%08x)\n", a->local_vtag);
}

static void handle_cookie_echo(int fd, const uint8_t *pkt, size_t pkt_len,
                               struct sockaddr_in *peer)
{
    if (pkt_len < 16) return;

    uint16_t src_port = get16(pkt + 0);
    uint16_t dst_port = get16(pkt + 2);

    /* Parse COOKIE-ECHO chunk at offset 12 */
    uint16_t chunk_len = get16(pkt + 14);
    if (chunk_len < 20) return; /* need 4 header + 16 cookie */

    /* Extract cookie */
    uint32_t c_local_vtag  = get32(pkt + 16);
    uint32_t c_remote_vtag = get32(pkt + 20);
    uint16_t c_local_port  = get16(pkt + 24);
    uint16_t c_remote_port = get16(pkt + 26);
    uint32_t c_magic       = get32(pkt + 28);

    if (c_magic != COOKIE_MAGIC) {
        printf("  COOKIE-ECHO: bad magic 0x%08x\n", c_magic);
        return;
    }

    printf("  COOKIE-ECHO from port %u, cookie valid\n", src_port);

    /* Find the association */
    struct assoc *a = find_assoc(c_local_port, c_remote_port, peer);
    if (!a) {
        printf("  COOKIE-ECHO: no matching association\n");
        return;
    }

    /* Build COOKIE-ACK response */
    uint8_t resp[32];
    memset(resp, 0, sizeof(resp));
    put16(resp + 0, dst_port);
    put16(resp + 2, src_port);
    put32(resp + 4, a->remote_vtag);
    /* COOKIE-ACK chunk: type=11, flags=0, length=4 */
    resp[12] = CHUNK_COOKIE_ACK;
    resp[13] = 0;
    put16(resp + 14, 4);
    size_t total = 16;
    stamp_checksum(resp, total);
    sendto(fd, resp, total, 0, (struct sockaddr *)peer, sizeof(*peer));
    printf("  → COOKIE-ACK sent, association ESTABLISHED\n");
}

static void handle_data(int fd, const uint8_t *pkt, size_t pkt_len,
                        struct sockaddr_in *peer)
{
    if (pkt_len < 28) return; /* 12 header + 16 DATA header minimum */

    uint16_t src_port = get16(pkt + 0);
    uint16_t dst_port = get16(pkt + 2);
    uint32_t vtag     = get32(pkt + 4);

    /* Parse DATA chunk at offset 12 */
    uint16_t chunk_len = get16(pkt + 14);
    if (chunk_len < 16) return;
    uint32_t tsn       = get32(pkt + 16);
    uint16_t stream_id = get16(pkt + 20);
    uint16_t ssn       = get16(pkt + 22);
    uint32_t ppid      = get32(pkt + 24);
    size_t payload_len = chunk_len - 16;
    const uint8_t *payload = pkt + 28;

    printf("  DATA: tsn=%u stream=%u ssn=%u len=%zu \"", tsn, stream_id, ssn, payload_len);
    for (size_t i = 0; i < payload_len && i < 32; i++)
        putchar(payload[i] >= 0x20 && payload[i] < 0x7f ? payload[i] : '.');
    printf("\"\n");

    /* Find association */
    struct assoc *a = find_assoc(dst_port, src_port, peer);
    if (!a) return;
    a->rcv_next_tsn = tsn + 1;

    /* Send SACK */
    uint8_t sack_pkt[32];
    memset(sack_pkt, 0, sizeof(sack_pkt));
    put16(sack_pkt + 0, a->local_port);
    put16(sack_pkt + 2, a->remote_port);
    put32(sack_pkt + 4, a->remote_vtag);
    sack_pkt[12] = CHUNK_SACK;
    sack_pkt[13] = 0;
    put16(sack_pkt + 14, 16);
    put32(sack_pkt + 16, tsn);      /* Cumulative TSN Ack */
    put32(sack_pkt + 20, 65535);    /* A-RWND */
    put16(sack_pkt + 24, 0);       /* Num Gap Blocks */
    put16(sack_pkt + 26, 0);       /* Num Dup TSNs */
    stamp_checksum(sack_pkt, 28);
    sendto(fd, sack_pkt, 28, 0, (struct sockaddr *)peer, sizeof(*peer));

    /* Echo: send DATA back with same payload */
    size_t echo_chunk_len = 16 + payload_len;
    size_t echo_padded = (echo_chunk_len + 3) & ~3u;
    size_t echo_total = 12 + echo_padded;
    uint8_t echo_pkt[MAX_PKT];
    memset(echo_pkt, 0, echo_total);
    put16(echo_pkt + 0, a->local_port);
    put16(echo_pkt + 2, a->remote_port);
    put32(echo_pkt + 4, a->remote_vtag);
    echo_pkt[12] = CHUNK_DATA;
    echo_pkt[13] = 0x03; /* B=1, E=1 */
    put16(echo_pkt + 14, echo_chunk_len);
    put32(echo_pkt + 16, a->next_tsn++);
    put16(echo_pkt + 20, stream_id);
    put16(echo_pkt + 22, a->next_ssn++);
    put32(echo_pkt + 24, ppid);
    memcpy(echo_pkt + 28, payload, payload_len);
    stamp_checksum(echo_pkt, echo_total);
    sendto(fd, echo_pkt, echo_total, 0, (struct sockaddr *)peer, sizeof(*peer));
    printf("  → SACK + DATA echo sent\n");
}

static void handle_heartbeat(int fd, const uint8_t *pkt, size_t pkt_len,
                             struct sockaddr_in *peer)
{
    if (pkt_len < 16) return;
    uint16_t src_port = get16(pkt + 0);
    uint16_t dst_port = get16(pkt + 2);

    struct assoc *a = find_assoc(dst_port, src_port, peer);
    if (!a) return;

    /* Copy the chunk and change type to HEARTBEAT-ACK */
    uint16_t chunk_len = get16(pkt + 14);
    size_t padded = (chunk_len + 3) & ~3u;
    size_t total = 12 + padded;
    if (total > MAX_PKT) return;

    uint8_t resp[MAX_PKT];
    memset(resp, 0, total);
    put16(resp + 0, dst_port);
    put16(resp + 2, src_port);
    put32(resp + 4, a->remote_vtag);
    memcpy(resp + 12, pkt + 12, padded);
    resp[12] = CHUNK_HEARTBEAT_ACK;
    stamp_checksum(resp, total);
    sendto(fd, resp, total, 0, (struct sockaddr *)peer, sizeof(*peer));
    printf("  → HEARTBEAT-ACK\n");
}

int main(void)
{
    crc32c_init();

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(UDP_ENCAP_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind");
        return 1;
    }

    printf("SCTP-over-UDP echo server listening on UDP port %d\n", UDP_ENCAP_PORT);
    printf("Waiting for SCTP associations (echo on SCTP port %d)...\n", SCTP_ECHO_PORT);

    while (1) {
        uint8_t buf[MAX_PKT];
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);

        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer, &peer_len);
        if (n < 12) continue;

        /* Verify SCTP checksum */
        uint32_t wire_cksum = (uint32_t)buf[8] | ((uint32_t)buf[9] << 8) |
                              ((uint32_t)buf[10] << 16) | ((uint32_t)buf[11] << 24);
        uint32_t calc_cksum = sctp_checksum(buf, n);
        if (wire_cksum != calc_cksum) {
            printf("  BAD CHECKSUM: wire=0x%08x calc=0x%08x (len=%zd)\n",
                   wire_cksum, calc_cksum, n);
            continue;
        }

        /* Dispatch based on first chunk type */
        if (n < 13) continue;
        uint8_t chunk_type = buf[12];

        switch (chunk_type) {
        case CHUNK_INIT:
            handle_init(fd, buf, n, &peer);
            break;
        case CHUNK_COOKIE_ECHO:
            handle_cookie_echo(fd, buf, n, &peer);
            break;
        case CHUNK_DATA:
            handle_data(fd, buf, n, &peer);
            break;
        case CHUNK_HEARTBEAT:
            handle_heartbeat(fd, buf, n, &peer);
            break;
        case CHUNK_SHUTDOWN:
            printf("  SHUTDOWN received\n");
            /* TODO: send SHUTDOWN-ACK */
            break;
        default:
            printf("  Unknown chunk type %u (len=%zd)\n", chunk_type, n);
            break;
        }
    }

    return 0;
}
