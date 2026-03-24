/* SSH-2 transport layer: version exchange, key exchange, packet encrypt/decrypt.
 * Implements curve25519-sha256 KEX, ssh-ed25519 host key, chacha20-poly1305@openssh.com. */
#include <telix/ssh.h>
#include <telix/crypto.h>
#include <telix/socket.h>
#include <string.h>

/* -- Low-level TCP I/O helpers -- */

static int tcp_send_all(int fd, const uint8_t *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int chunk = len - sent;
        if (chunk > 16) chunk = 16; /* TCP send chunks limited by IPC. */
        ssize_t n = send(fd, buf + sent, chunk, 0);
        if (n <= 0) return -1;
        sent += (int)n;
    }
    return 0;
}

static int tcp_recv_all(int fd, uint8_t *buf, int len) {
    int got = 0;
    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) return -1;
        got += (int)n;
    }
    return 0;
}

/* Read a line (up to \n or maxlen). Returns length including \n, or -1. */
static int tcp_recv_line(int fd, char *buf, int maxlen) {
    int pos = 0;
    while (pos < maxlen - 1) {
        uint8_t c;
        if (tcp_recv_all(fd, &c, 1) != 0) return -1;
        buf[pos++] = (char)c;
        if (c == '\n') break;
    }
    buf[pos] = '\0';
    return pos;
}

/* -- Serialization helpers -- */

void ssh_put_uint32(uint8_t *buf, uint32_t v) {
    buf[0]=(uint8_t)(v>>24); buf[1]=(uint8_t)(v>>16);
    buf[2]=(uint8_t)(v>>8);  buf[3]=(uint8_t)v;
}

uint32_t ssh_get_uint32(const uint8_t *buf) {
    return ((uint32_t)buf[0]<<24)|((uint32_t)buf[1]<<16)|
           ((uint32_t)buf[2]<<8)|buf[3];
}

void ssh_put_string(uint8_t *buf, int *pos, const uint8_t *data, int len) {
    ssh_put_uint32(buf + *pos, (uint32_t)len);
    *pos += 4;
    memcpy(buf + *pos, data, len);
    *pos += len;
}

void ssh_put_cstring(uint8_t *buf, int *pos, const char *s) {
    int len = 0;
    while (s[len]) len++;
    ssh_put_string(buf, pos, (const uint8_t *)s, len);
}

int ssh_get_string(const uint8_t *buf, int pos, int buf_len,
                   const uint8_t **out, int *out_len) {
    if (pos + 4 > buf_len) return -1;
    uint32_t slen = ssh_get_uint32(buf + pos);
    if (pos + 4 + (int)slen > buf_len) return -1;
    *out = buf + pos + 4;
    *out_len = (int)slen;
    return pos + 4 + (int)slen;
}

/* -- Transport init -- */

void ssh_transport_init(ssh_transport *t, int fd,
                        const uint8_t host_pk[32], const uint8_t host_sk[64]) {
    memset(t, 0, sizeof(*t));
    t->fd = fd;
    memcpy(t->host_pk, host_pk, 32);
    memcpy(t->host_sk, host_sk, 64);
}

/* -- Version exchange (RFC 4253 section 4.2) -- */

static const char *SERVER_VERSION = "SSH-2.0-Telix_0.1\r\n";

int ssh_version_exchange(ssh_transport *t) {
    /* Send our version string. */
    int vlen = 0;
    while (SERVER_VERSION[vlen]) vlen++;
    memcpy(t->server_version, SERVER_VERSION, vlen);
    t->server_version[vlen] = '\0';
    /* Strip \r\n for the version stored internally. */

    if (tcp_send_all(t->fd, (const uint8_t *)SERVER_VERSION, vlen) != 0)
        return -1;

    /* Receive client version string. */
    int n = tcp_recv_line(t->fd, t->client_version, sizeof(t->client_version));
    if (n < 4) return -1;

    /* Must start with "SSH-2.0-" */
    if (t->client_version[0]!='S' || t->client_version[1]!='S' ||
        t->client_version[2]!='H' || t->client_version[3]!='-')
        return -1;

    return 0;
}

/* -- Unencrypted packet send/recv (before NEWKEYS) -- */

static int send_packet_plain(ssh_transport *t, const uint8_t *payload, int plen) {
    /* Binary packet: uint32 packet_length, byte padding_length, payload, padding.
     * packet_length = 1 + plen + padding_len. */
    int block_size = 8;
    int total = 4 + 1 + plen;
    int padding = block_size - (total % block_size);
    if (padding < 4) padding += block_size;
    int packet_len = 1 + plen + padding;

    uint8_t hdr[5];
    ssh_put_uint32(hdr, (uint32_t)packet_len);
    hdr[4] = (uint8_t)padding;

    if (tcp_send_all(t->fd, hdr, 5) != 0) return -1;
    if (plen > 0 && tcp_send_all(t->fd, payload, plen) != 0) return -1;

    uint8_t pad[32];
    memset(pad, 0, padding);
    if (tcp_send_all(t->fd, pad, padding) != 0) return -1;

    t->seq_send++;
    return 0;
}

static int recv_packet_plain(ssh_transport *t, uint8_t *payload, int max_payload) {
    uint8_t hdr[5];
    if (tcp_recv_all(t->fd, hdr, 5) != 0) return -1;

    uint32_t packet_len = ssh_get_uint32(hdr);
    if (packet_len < 1 || packet_len > SSH_MAX_PACKET) return -1;

    uint8_t padding_len = hdr[4];
    int payload_len = (int)packet_len - 1 - padding_len;
    if (payload_len < 0 || payload_len > max_payload) return -1;

    if (payload_len > 0) {
        if (tcp_recv_all(t->fd, payload, payload_len) != 0) return -1;
    }

    /* Read and discard padding. */
    uint8_t pad[256];
    if (padding_len > 0) {
        if (tcp_recv_all(t->fd, pad, padding_len) != 0) return -1;
    }

    t->seq_recv++;
    return payload_len;
}

/* -- ChaCha20-Poly1305@openssh.com encrypted packet I/O -- */

/* The openssh chacha20-poly1305 construction uses two ChaCha20 instances per packet:
 * - K1 (first 32 bytes of key): encrypts the 4-byte packet length
 * - K2 (last 32 bytes of key): encrypts the payload, generates MAC
 * Nonce is the sequence number as big-endian 8 bytes, padded to 12 bytes with 4 zero bytes. */

static void make_nonce(uint8_t nonce[12], uint32_t seq) {
    memset(nonce, 0, 12);
    nonce[8]  = (uint8_t)(seq >> 24);
    nonce[9]  = (uint8_t)(seq >> 16);
    nonce[10] = (uint8_t)(seq >> 8);
    nonce[11] = (uint8_t)seq;
}

static int send_packet_encrypted(ssh_transport *t, const uint8_t *payload, int plen) {
    /* K1 = enc_key[0..31], K2 = enc_key[32..63] for server->client. */
    const uint8_t *K1 = t->enc_key_sc;
    const uint8_t *K2 = t->enc_key_sc + 32;

    int block_size = 8;
    int total = 4 + 1 + plen;
    int padding = block_size - (total % block_size);
    if (padding < 4) padding += block_size;
    int packet_len = 1 + plen + padding;

    /* Encrypt packet_length with K1. */
    uint8_t plen_buf[4], enc_plen[4];
    ssh_put_uint32(plen_buf, (uint32_t)packet_len);
    uint8_t nonce[12];
    make_nonce(nonce, t->seq_send);
    chacha20_encrypt(K1, 0, nonce, plen_buf, enc_plen, 4);

    /* Build plaintext: padding_length || payload || padding. */
    int pt_len = 1 + plen + padding;
    uint8_t pt[SSH_MAX_PACKET];
    pt[0] = (uint8_t)padding;
    if (plen > 0) memcpy(pt + 1, payload, plen);
    memset(pt + 1 + plen, 0, padding);

    /* Encrypt with K2 (counter starts at 1 since counter 0 generates Poly1305 key). */
    uint8_t ct[SSH_MAX_PACKET];
    chacha20_encrypt(K2, 1, nonce, pt, ct, pt_len);

    /* Compute Poly1305 MAC over encrypted_length || ciphertext. */
    uint8_t poly_key[64];
    chacha20_block(K2, 0, nonce, poly_key);

    /* MAC input: enc_plen (4 bytes) || ct (pt_len bytes). */
    uint8_t mac_input[SSH_MAX_PACKET + 4];
    memcpy(mac_input, enc_plen, 4);
    memcpy(mac_input + 4, ct, pt_len);
    uint8_t mac[16];
    poly1305_mac(mac_input, 4 + pt_len, poly_key, mac);

    /* Send: enc_plen || ct || mac. */
    if (tcp_send_all(t->fd, enc_plen, 4) != 0) return -1;
    if (tcp_send_all(t->fd, ct, pt_len) != 0) return -1;
    if (tcp_send_all(t->fd, mac, 16) != 0) return -1;

    t->seq_send++;
    return 0;
}

static int recv_packet_encrypted(ssh_transport *t, uint8_t *payload, int max_payload) {
    /* K1 = enc_key[0..31], K2 = enc_key[32..63] for client->server. */
    const uint8_t *K1 = t->enc_key_cs;
    const uint8_t *K2 = t->enc_key_cs + 32;

    uint8_t nonce[12];
    make_nonce(nonce, t->seq_recv);

    /* Read encrypted packet length (4 bytes). */
    uint8_t enc_plen[4];
    if (tcp_recv_all(t->fd, enc_plen, 4) != 0) return -1;

    /* Decrypt packet length with K1. */
    uint8_t plen_buf[4];
    chacha20_encrypt(K1, 0, nonce, enc_plen, plen_buf, 4);
    uint32_t packet_len = ssh_get_uint32(plen_buf);
    if (packet_len < 1 || packet_len > SSH_MAX_PACKET) return -1;

    /* Read ciphertext (packet_len bytes). */
    uint8_t ct[SSH_MAX_PACKET];
    if (tcp_recv_all(t->fd, ct, (int)packet_len) != 0) return -1;

    /* Read MAC (16 bytes). */
    uint8_t recv_mac[16];
    if (tcp_recv_all(t->fd, recv_mac, 16) != 0) return -1;

    /* Verify Poly1305 MAC. */
    uint8_t poly_key[64];
    chacha20_block(K2, 0, nonce, poly_key);

    uint8_t mac_input[SSH_MAX_PACKET + 4];
    memcpy(mac_input, enc_plen, 4);
    memcpy(mac_input + 4, ct, packet_len);
    uint8_t computed_mac[16];
    poly1305_mac(mac_input, 4 + packet_len, poly_key, computed_mac);

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= recv_mac[i] ^ computed_mac[i];
    if (diff != 0) return -1; /* MAC verification failed. */

    /* Decrypt payload with K2 (counter=1). */
    uint8_t pt[SSH_MAX_PACKET];
    chacha20_encrypt(K2, 1, nonce, ct, pt, (int)packet_len);

    uint8_t padding_len = pt[0];
    int payload_len = (int)packet_len - 1 - padding_len;
    if (payload_len < 0 || payload_len > max_payload) return -1;

    if (payload_len > 0) memcpy(payload, pt + 1, payload_len);

    t->seq_recv++;
    return payload_len;
}

/* -- Public packet API -- */

int ssh_recv_packet(ssh_transport *t, uint8_t *payload_out) {
    if (t->keys_active)
        return recv_packet_encrypted(t, payload_out, SSH_MAX_PAYLOAD);
    else
        return recv_packet_plain(t, payload_out, SSH_MAX_PAYLOAD);
}

int ssh_send_packet(ssh_transport *t, const uint8_t *payload, int len) {
    if (t->keys_active)
        return send_packet_encrypted(t, payload, len);
    else
        return send_packet_plain(t, payload, len);
}

/* -- Key Exchange -- */

/* Build KEXINIT packet. */
static int build_kexinit(uint8_t *buf) {
    int pos = 0;
    buf[pos++] = SSH_MSG_KEXINIT;

    /* 16 bytes cookie (random). */
    csprng_bytes(buf + pos, 16);
    pos += 16;

    /* Algorithm lists (name-lists). */
    /* kex_algorithms */
    ssh_put_cstring(buf, &pos, "curve25519-sha256,curve25519-sha256@libssh.org");
    /* server_host_key_algorithms */
    ssh_put_cstring(buf, &pos, "ssh-ed25519");
    /* encryption_algorithms_client_to_server */
    ssh_put_cstring(buf, &pos, "chacha20-poly1305@openssh.com");
    /* encryption_algorithms_server_to_client */
    ssh_put_cstring(buf, &pos, "chacha20-poly1305@openssh.com");
    /* mac_algorithms_client_to_server */
    ssh_put_cstring(buf, &pos, "none");
    /* mac_algorithms_server_to_client */
    ssh_put_cstring(buf, &pos, "none");
    /* compression_algorithms_client_to_server */
    ssh_put_cstring(buf, &pos, "none");
    /* compression_algorithms_server_to_client */
    ssh_put_cstring(buf, &pos, "none");
    /* languages_client_to_server */
    ssh_put_cstring(buf, &pos, "");
    /* languages_server_to_client */
    ssh_put_cstring(buf, &pos, "");
    /* first_kex_packet_follows */
    buf[pos++] = 0;
    /* reserved */
    ssh_put_uint32(buf + pos, 0);
    pos += 4;

    return pos;
}

/* Derive a key from the exchange hash per RFC 4253 section 7.2. */
static void derive_key(uint8_t *out, int out_len,
                       const uint8_t *shared_secret, int ss_len,
                       const uint8_t exchange_hash[32],
                       uint8_t letter,
                       const uint8_t session_id[32]) {
    /* K_letter = HASH(K || H || letter || session_id) */
    sha256_ctx ctx;
    sha256_init(&ctx);
    /* K is encoded as mpint. */
    sha256_update(&ctx, shared_secret, ss_len);
    sha256_update(&ctx, exchange_hash, 32);
    sha256_update(&ctx, &letter, 1);
    sha256_update(&ctx, session_id, 32);
    uint8_t hash[32];
    sha256_final(&ctx, hash);

    int copied = 32 < out_len ? 32 : out_len;
    memcpy(out, hash, copied);

    /* If we need more than 32 bytes, extend. */
    while (copied < out_len) {
        sha256_init(&ctx);
        sha256_update(&ctx, shared_secret, ss_len);
        sha256_update(&ctx, exchange_hash, 32);
        sha256_update(&ctx, out, copied);
        sha256_final(&ctx, hash);
        int chunk = 32 < (out_len - copied) ? 32 : (out_len - copied);
        memcpy(out + copied, hash, chunk);
        copied += chunk;
    }
}

/* Encode a 256-bit value as SSH mpint (with leading zero if high bit set). */
static int encode_mpint(uint8_t *buf, const uint8_t val[32]) {
    int pos = 0;
    int start = 0;
    /* Find first non-zero byte. */
    while (start < 32 && val[start] == 0) start++;
    if (start == 32) {
        /* Zero value. */
        ssh_put_uint32(buf, 1);
        buf[4] = 0;
        return 5;
    }
    int len = 32 - start;
    int need_pad = (val[start] & 0x80) ? 1 : 0;
    ssh_put_uint32(buf, (uint32_t)(len + need_pad));
    pos = 4;
    if (need_pad) buf[pos++] = 0;
    memcpy(buf + pos, val + start, len);
    return 4 + len + need_pad;
}

/* Encode shared secret K as mpint from 32-byte x25519 output (big-endian). */
static int encode_shared_secret(uint8_t *buf, const uint8_t k_le[32]) {
    /* x25519 output is little-endian. Convert to big-endian for SSH mpint. */
    uint8_t k_be[32];
    for (int i = 0; i < 32; i++) k_be[i] = k_le[31-i];
    return encode_mpint(buf, k_be);
}

int ssh_key_exchange(ssh_transport *t) {
    csprng_init();

    /* Step 1: Send our KEXINIT. */
    uint8_t kex_payload[1024];
    int kex_len = build_kexinit(kex_payload);
    memcpy(t->server_kexinit, kex_payload, kex_len);
    t->server_kexinit_len = kex_len;

    if (ssh_send_packet(t, kex_payload, kex_len) != 0) return -1;

    /* Step 2: Receive client KEXINIT. */
    uint8_t client_kex[2048];
    int ck_len = ssh_recv_packet(t, client_kex);
    if (ck_len < 1 || client_kex[0] != SSH_MSG_KEXINIT) return -1;
    memcpy(t->client_kexinit, client_kex, ck_len);
    t->client_kexinit_len = ck_len;

    /* Step 3: Receive KEX_ECDH_INIT from client (contains client's ephemeral public key). */
    uint8_t ecdh_init[256];
    int ei_len = ssh_recv_packet(t, ecdh_init);
    if (ei_len < 1 || ecdh_init[0] != SSH_MSG_KEX_ECDH_INIT) return -1;

    /* Extract Q_C (client's ephemeral public key). */
    const uint8_t *q_c;
    int q_c_len;
    if (ssh_get_string(ecdh_init, 1, ei_len, &q_c, &q_c_len) < 0) return -1;
    if (q_c_len != 32) return -1;

    /* Step 4: Generate our ephemeral key pair. */
    uint8_t eph_secret[32], eph_public[32];
    csprng_bytes(eph_secret, 32);
    x25519_base(eph_public, eph_secret);

    /* Step 5: Compute shared secret K = x25519(eph_secret, Q_C). */
    uint8_t shared_k[32];
    x25519(shared_k, eph_secret, q_c);

    /* Step 6: Build exchange hash H = SHA-256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K). */
    sha256_ctx hctx;
    sha256_init(&hctx);

    /* V_C: client version string (without \r\n). */
    {
        int vlen = 0;
        while (t->client_version[vlen] && t->client_version[vlen] != '\r' && t->client_version[vlen] != '\n')
            vlen++;
        uint8_t lbuf[4];
        ssh_put_uint32(lbuf, (uint32_t)vlen);
        sha256_update(&hctx, lbuf, 4);
        sha256_update(&hctx, (const uint8_t *)t->client_version, vlen);
    }

    /* V_S: server version string (without \r\n). */
    {
        int vlen = 0;
        const char *sv = "SSH-2.0-Telix_0.1";
        while (sv[vlen]) vlen++;
        uint8_t lbuf[4];
        ssh_put_uint32(lbuf, (uint32_t)vlen);
        sha256_update(&hctx, lbuf, 4);
        sha256_update(&hctx, (const uint8_t *)sv, vlen);
    }

    /* I_C: client KEXINIT payload. */
    {
        uint8_t lbuf[4];
        ssh_put_uint32(lbuf, (uint32_t)t->client_kexinit_len);
        sha256_update(&hctx, lbuf, 4);
        sha256_update(&hctx, t->client_kexinit, t->client_kexinit_len);
    }

    /* I_S: server KEXINIT payload. */
    {
        uint8_t lbuf[4];
        ssh_put_uint32(lbuf, (uint32_t)t->server_kexinit_len);
        sha256_update(&hctx, lbuf, 4);
        sha256_update(&hctx, t->server_kexinit, t->server_kexinit_len);
    }

    /* K_S: host key blob = string("ssh-ed25519") || string(pk). */
    {
        uint8_t ks_blob[256];
        int ks_len = 0;
        ssh_put_cstring(ks_blob, &ks_len, "ssh-ed25519");
        ssh_put_string(ks_blob, &ks_len, t->host_pk, 32);

        uint8_t lbuf[4];
        ssh_put_uint32(lbuf, (uint32_t)ks_len);
        sha256_update(&hctx, lbuf, 4);
        sha256_update(&hctx, ks_blob, ks_len);
    }

    /* Q_C: client ephemeral key. */
    {
        uint8_t lbuf[4];
        ssh_put_uint32(lbuf, 32);
        sha256_update(&hctx, lbuf, 4);
        sha256_update(&hctx, q_c, 32);
    }

    /* Q_S: server ephemeral key. */
    {
        uint8_t lbuf[4];
        ssh_put_uint32(lbuf, 32);
        sha256_update(&hctx, lbuf, 4);
        sha256_update(&hctx, eph_public, 32);
    }

    /* K: shared secret as mpint. */
    {
        uint8_t k_mpint[40];
        int k_mpint_len = encode_shared_secret(k_mpint, shared_k);
        sha256_update(&hctx, k_mpint, k_mpint_len);
    }

    uint8_t exchange_hash[32];
    sha256_final(&hctx, exchange_hash);

    /* Set session_id if first exchange. */
    if (!t->session_id_set) {
        memcpy(t->session_id, exchange_hash, 32);
        t->session_id_set = 1;
    }

    /* Step 7: Sign exchange hash with host key. */
    uint8_t sig[64];
    ed25519_sign(sig, exchange_hash, 32, t->host_pk, t->host_sk);

    /* Step 8: Send KEX_ECDH_REPLY. */
    {
        uint8_t reply[512];
        int rpos = 0;
        reply[rpos++] = SSH_MSG_KEX_ECDH_REPLY;

        /* K_S: host key blob. */
        uint8_t ks_blob[256];
        int ks_len = 0;
        ssh_put_cstring(ks_blob, &ks_len, "ssh-ed25519");
        ssh_put_string(ks_blob, &ks_len, t->host_pk, 32);
        ssh_put_string(reply, &rpos, ks_blob, ks_len);

        /* Q_S: server ephemeral public key. */
        ssh_put_string(reply, &rpos, eph_public, 32);

        /* Signature blob: string("ssh-ed25519") || string(sig). */
        uint8_t sig_blob[256];
        int sig_len = 0;
        ssh_put_cstring(sig_blob, &sig_len, "ssh-ed25519");
        ssh_put_string(sig_blob, &sig_len, sig, 64);
        ssh_put_string(reply, &rpos, sig_blob, sig_len);

        if (ssh_send_packet(t, reply, rpos) != 0) return -1;
    }

    /* Step 9: Send NEWKEYS. */
    {
        uint8_t nk = SSH_MSG_NEWKEYS;
        if (ssh_send_packet(t, &nk, 1) != 0) return -1;
    }

    /* Step 10: Receive NEWKEYS from client. */
    {
        uint8_t nk_buf[16];
        int nk_len = ssh_recv_packet(t, nk_buf);
        if (nk_len < 1 || nk_buf[0] != SSH_MSG_NEWKEYS) return -1;
    }

    /* Step 11: Derive session keys.
     * For chacha20-poly1305@openssh.com, we need 64 bytes per direction (two 32-byte keys). */
    uint8_t k_mpint[40];
    int k_mpint_len = encode_shared_secret(k_mpint, shared_k);

    /* Client->server encryption key (64 bytes). */
    derive_key(t->enc_key_cs, 64, k_mpint, k_mpint_len, exchange_hash, 'C', t->session_id);
    /* Server->client encryption key (64 bytes). */
    derive_key(t->enc_key_sc, 64, k_mpint, k_mpint_len, exchange_hash, 'D', t->session_id);
    /* Integrity keys (not used for chacha20-poly1305 but derive anyway). */
    derive_key(t->int_key_cs, 64, k_mpint, k_mpint_len, exchange_hash, 'E', t->session_id);
    derive_key(t->int_key_sc, 64, k_mpint, k_mpint_len, exchange_hash, 'F', t->session_id);

    t->keys_active = 1;
    return 0;
}
