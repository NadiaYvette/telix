/* ChaCha20 + Poly1305 AEAD - pure 32-bit integer, no FP.
 * Implements RFC 7539 (ChaCha20-Poly1305). */
#include <telix/crypto.h>
#include <string.h>

/* -- ChaCha20 core -- */

#define ROTL32(v,n) (((v)<<(n))|((v)>>(32-(n))))
#define QR(a,b,c,d) \
    a+=b; d^=a; d=ROTL32(d,16); \
    c+=d; b^=c; b=ROTL32(b,12); \
    a+=b; d^=a; d=ROTL32(d,8);  \
    c+=d; b^=c; b=ROTL32(b,7)

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}

static void put_le32(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}

static void put_le64(uint8_t *p, uint64_t v) {
    for (int i=0;i<8;i++) { p[i]=(uint8_t)v; v>>=8; }
}

void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                    uint8_t out[64]) {
    uint32_t s[16];
    /* "expand 32-byte k" */
    s[0]=0x61707865; s[1]=0x3320646e; s[2]=0x79622d32; s[3]=0x6b206574;
    for (int i=0;i<8;i++) s[4+i]=le32(key+i*4);
    s[12]=counter;
    s[13]=le32(nonce+0); s[14]=le32(nonce+4); s[15]=le32(nonce+8);

    uint32_t w[16];
    for (int i=0;i<16;i++) w[i]=s[i];

    for (int i=0;i<10;i++) {
        QR(w[0],w[4],w[8],w[12]);  QR(w[1],w[5],w[9],w[13]);
        QR(w[2],w[6],w[10],w[14]); QR(w[3],w[7],w[11],w[15]);
        QR(w[0],w[5],w[10],w[15]); QR(w[1],w[6],w[11],w[12]);
        QR(w[2],w[7],w[8],w[13]);  QR(w[3],w[4],w[9],w[14]);
    }

    for (int i=0;i<16;i++) put_le32(out+i*4, w[i]+s[i]);
}

void chacha20_encrypt(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                      const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t block[64];
    for (size_t i=0; i<len; i+=64) {
        chacha20_block(key, counter++, nonce, block);
        size_t chunk = len-i;
        if (chunk>64) chunk=64;
        for (size_t j=0;j<chunk;j++) out[i+j]=in[i+j]^block[j];
    }
}

/* -- Poly1305 MAC -- */

/* Poly1305 uses 130-bit arithmetic. We represent numbers in 5 limbs of 26 bits. */
typedef struct {
    uint32_t h[5];   /* accumulator */
    uint32_t r[5];   /* clamped key r */
    uint32_t pad[4]; /* key s */
} poly1305_state;

static void poly1305_init(poly1305_state *st, const uint8_t key[32]) {
    /* r = key[0..15] clamped */
    uint32_t t0=le32(key+0), t1=le32(key+4), t2=le32(key+8), t3=le32(key+12);
    st->r[0] = t0 & 0x3ffffff;
    st->r[1] = ((t0>>26)|(t1<<6)) & 0x3ffff03;
    st->r[2] = ((t1>>20)|(t2<<12)) & 0x3ffc0ff;
    st->r[3] = ((t2>>14)|(t3<<18)) & 0x3f03fff;
    st->r[4] = (t3>>8) & 0x00fffff;

    /* s = key[16..31] */
    st->pad[0]=le32(key+16); st->pad[1]=le32(key+20);
    st->pad[2]=le32(key+24); st->pad[3]=le32(key+28);

    for (int i=0;i<5;i++) st->h[i]=0;
}

static void poly1305_blocks(poly1305_state *st, const uint8_t *data, size_t len, uint32_t hibit) {
    uint32_t r0=st->r[0],r1=st->r[1],r2=st->r[2],r3=st->r[3],r4=st->r[4];
    uint32_t s1=r1*5,s2=r2*5,s3=r3*5,s4=r4*5;
    uint32_t h0=st->h[0],h1=st->h[1],h2=st->h[2],h3=st->h[3],h4=st->h[4];

    while (len >= 16) {
        uint32_t t0=le32(data+0),t1=le32(data+4),t2=le32(data+8),t3=le32(data+12);
        h0 += t0 & 0x3ffffff;
        h1 += ((t0>>26)|(t1<<6)) & 0x3ffffff;
        h2 += ((t1>>20)|(t2<<12)) & 0x3ffffff;
        h3 += ((t2>>14)|(t3<<18)) & 0x3ffffff;
        h4 += (t3>>8) | hibit;

        uint64_t d0=(uint64_t)h0*r0+(uint64_t)h1*s4+(uint64_t)h2*s3+(uint64_t)h3*s2+(uint64_t)h4*s1;
        uint64_t d1=(uint64_t)h0*r1+(uint64_t)h1*r0+(uint64_t)h2*s4+(uint64_t)h3*s3+(uint64_t)h4*s2;
        uint64_t d2=(uint64_t)h0*r2+(uint64_t)h1*r1+(uint64_t)h2*r0+(uint64_t)h3*s4+(uint64_t)h4*s3;
        uint64_t d3=(uint64_t)h0*r3+(uint64_t)h1*r2+(uint64_t)h2*r1+(uint64_t)h3*r0+(uint64_t)h4*s4;
        uint64_t d4=(uint64_t)h0*r4+(uint64_t)h1*r3+(uint64_t)h2*r2+(uint64_t)h3*r1+(uint64_t)h4*r0;

        uint32_t c;
        c=(uint32_t)(d0>>26); h0=(uint32_t)d0&0x3ffffff; d1+=c;
        c=(uint32_t)(d1>>26); h1=(uint32_t)d1&0x3ffffff; d2+=c;
        c=(uint32_t)(d2>>26); h2=(uint32_t)d2&0x3ffffff; d3+=c;
        c=(uint32_t)(d3>>26); h3=(uint32_t)d3&0x3ffffff; d4+=c;
        c=(uint32_t)(d4>>26); h4=(uint32_t)d4&0x3ffffff; h0+=c*5;
        c=h0>>26; h0&=0x3ffffff; h1+=c;

        data+=16; len-=16;
    }
    st->h[0]=h0; st->h[1]=h1; st->h[2]=h2; st->h[3]=h3; st->h[4]=h4;
}

static void poly1305_finish(poly1305_state *st, uint8_t tag[16]) {
    /* Process remaining bytes (handled by caller padding). */
    uint32_t h0=st->h[0],h1=st->h[1],h2=st->h[2],h3=st->h[3],h4=st->h[4];
    uint32_t c;

    /* Full carry and reduce. */
    c=h1>>26; h1&=0x3ffffff; h2+=c;
    c=h2>>26; h2&=0x3ffffff; h3+=c;
    c=h3>>26; h3&=0x3ffffff; h4+=c;
    c=h4>>26; h4&=0x3ffffff; h0+=c*5;
    c=h0>>26; h0&=0x3ffffff; h1+=c;

    /* Compute h - p. */
    uint32_t g0=h0+5; c=g0>>26; g0&=0x3ffffff;
    uint32_t g1=h1+c; c=g1>>26; g1&=0x3ffffff;
    uint32_t g2=h2+c; c=g2>>26; g2&=0x3ffffff;
    uint32_t g3=h3+c; c=g3>>26; g3&=0x3ffffff;
    uint32_t g4=h4+c-(1<<26);

    /* Select h or g. */
    uint32_t mask = (g4>>31)-1; /* 0 if h < p, ~0 if h >= p */
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0&mask)|g0; h1 = (h1&mask)|g1; h2 = (h2&mask)|g2;
    h3 = (h3&mask)|g3; h4 = (h4&mask)|g4;

    /* h = h + pad */
    uint64_t f;
    uint32_t t0 = h0 | (h1<<26);
    uint32_t t1 = (h1>>6) | (h2<<20);
    uint32_t t2 = (h2>>12) | (h3<<14);
    uint32_t t3 = (h3>>18) | (h4<<8);

    f = (uint64_t)t0 + st->pad[0]; t0=(uint32_t)f;
    f = (uint64_t)t1 + st->pad[1] + (f>>32); t1=(uint32_t)f;
    f = (uint64_t)t2 + st->pad[2] + (f>>32); t2=(uint32_t)f;
    f = (uint64_t)t3 + st->pad[3] + (f>>32); t3=(uint32_t)f;

    put_le32(tag+0, t0); put_le32(tag+4, t1);
    put_le32(tag+8, t2); put_le32(tag+12, t3);
}

void poly1305_mac(const uint8_t *msg, size_t len, const uint8_t key[32],
                  uint8_t tag[16]) {
    poly1305_state st;
    poly1305_init(&st, key);

    /* Process full blocks. */
    size_t full = len & ~(size_t)15;
    if (full > 0) poly1305_blocks(&st, msg, full, 1<<24);

    /* Process final partial block. */
    size_t rem = len - full;
    if (rem > 0) {
        uint8_t pad[16];
        memset(pad, 0, 16);
        memcpy(pad, msg+full, rem);
        pad[rem] = 1;
        poly1305_blocks(&st, pad, 16, 0);
    }

    poly1305_finish(&st, tag);
}

/* -- ChaCha20-Poly1305 AEAD (RFC 7539) -- */

static void pad16(uint8_t *mac_data, size_t *mac_len, size_t data_len) {
    size_t rem = data_len % 16;
    if (rem > 0) {
        uint8_t zeros[16];
        memset(zeros, 0, 16);
        /* This is simplified - we'll compute the MAC inline instead. */
        (void)mac_data; (void)mac_len;
        (void)zeros;
    }
}

int chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *plaintext, size_t pt_len,
                              uint8_t *ciphertext, uint8_t tag[16]) {
    /* Generate Poly1305 key (counter=0). */
    uint8_t poly_key[64];
    chacha20_block(key, 0, nonce, poly_key);

    /* Encrypt plaintext (counter starts at 1). */
    chacha20_encrypt(key, 1, nonce, plaintext, ciphertext, pt_len);

    /* Build MAC input: aad || pad(aad) || ct || pad(ct) || le64(aad_len) || le64(ct_len) */
    /* We compute Poly1305 incrementally. */
    poly1305_state st;
    poly1305_init(&st, poly_key);

    /* Process AAD with padding. */
    size_t full = aad_len & ~(size_t)15;
    if (full > 0) poly1305_blocks(&st, aad, full, 1<<24);
    if (aad_len > full) {
        uint8_t pad[16]; memset(pad,0,16);
        memcpy(pad, aad+full, aad_len-full);
        poly1305_blocks(&st, pad, 16, 1<<24);
    } else if (aad_len == 0) {
        /* No AAD, no padding needed. */
    }

    /* Process ciphertext with padding. */
    full = pt_len & ~(size_t)15;
    if (full > 0) poly1305_blocks(&st, ciphertext, full, 1<<24);
    if (pt_len > full) {
        uint8_t pad[16]; memset(pad,0,16);
        memcpy(pad, ciphertext+full, pt_len-full);
        poly1305_blocks(&st, pad, 16, 1<<24);
    }

    /* Process lengths. */
    uint8_t lens[16];
    put_le64(lens, aad_len);
    put_le64(lens+8, pt_len);
    poly1305_blocks(&st, lens, 16, 1<<24);

    poly1305_finish(&st, tag);
    (void)pad16;
    return 0;
}

int chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ciphertext, size_t ct_len,
                              uint8_t *plaintext, const uint8_t tag[16]) {
    /* Generate Poly1305 key (counter=0). */
    uint8_t poly_key[64];
    chacha20_block(key, 0, nonce, poly_key);

    /* Verify MAC first. */
    poly1305_state st;
    poly1305_init(&st, poly_key);

    size_t full = aad_len & ~(size_t)15;
    if (full > 0) poly1305_blocks(&st, aad, full, 1<<24);
    if (aad_len > full) {
        uint8_t pad[16]; memset(pad,0,16);
        memcpy(pad, aad+full, aad_len-full);
        poly1305_blocks(&st, pad, 16, 1<<24);
    }

    full = ct_len & ~(size_t)15;
    if (full > 0) poly1305_blocks(&st, ciphertext, full, 1<<24);
    if (ct_len > full) {
        uint8_t pad[16]; memset(pad,0,16);
        memcpy(pad, ciphertext+full, ct_len-full);
        poly1305_blocks(&st, pad, 16, 1<<24);
    }

    uint8_t lens[16];
    put_le64(lens, aad_len);
    put_le64(lens+8, ct_len);
    poly1305_blocks(&st, lens, 16, 1<<24);

    uint8_t computed_tag[16];
    poly1305_finish(&st, computed_tag);

    /* Constant-time compare. */
    uint8_t diff = 0;
    for (int i=0;i<16;i++) diff |= computed_tag[i] ^ tag[i];
    if (diff != 0) return -1;

    /* Decrypt. */
    chacha20_encrypt(key, 1, nonce, ciphertext, plaintext, ct_len);
    return 0;
}
