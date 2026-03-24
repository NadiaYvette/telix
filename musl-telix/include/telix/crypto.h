/* Telix crypto primitives - all integer-only, no floating point. */
#ifndef TELIX_CRYPTO_H
#define TELIX_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* SHA-256 */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t hash[32]);
void sha256(const uint8_t *data, size_t len, uint8_t hash[32]);

/* SHA-512 */
typedef struct {
    uint64_t state[8];
    uint64_t count;
    uint8_t  buf[128];
} sha512_ctx;

void sha512_init(sha512_ctx *ctx);
void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len);
void sha512_final(sha512_ctx *ctx, uint8_t hash[64]);
void sha512(const uint8_t *data, size_t len, uint8_t hash[64]);

/* ChaCha20 */
void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                    uint8_t out[64]);
void chacha20_encrypt(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                      const uint8_t *in, uint8_t *out, size_t len);

/* Poly1305 */
void poly1305_mac(const uint8_t *msg, size_t len, const uint8_t key[32],
                  uint8_t tag[16]);

/* ChaCha20-Poly1305 AEAD (RFC 7539) */
int chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *plaintext, size_t pt_len,
                              uint8_t *ciphertext, uint8_t tag[16]);
int chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *ciphertext, size_t ct_len,
                              uint8_t *plaintext, const uint8_t tag[16]);

/* X25519 (Curve25519 ECDH) */
void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
void x25519_base(uint8_t out[32], const uint8_t scalar[32]);

/* Ed25519 */
void ed25519_create_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]);
void ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                  const uint8_t pk[32], const uint8_t sk[64]);
int  ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                    const uint8_t pk[32]);

/* CSPRNG */
void csprng_init(void);
void csprng_bytes(uint8_t *buf, size_t len);

/* HMAC-SHA-256 */
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t mac[32]);

#endif /* TELIX_CRYPTO_H */
