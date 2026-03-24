/* ChaCha20-based CSPRNG for Telix.
 * Seeds from getrandom() (kernel PRNG), stretches with ChaCha20. */
#include <telix/crypto.h>
#include <telix/syscall.h>
#include <string.h>

#define SYS_GETRANDOM 96

static uint8_t csprng_key[32];
static uint32_t csprng_counter;
static uint8_t csprng_buf[64];
static int csprng_buf_pos;
static int csprng_seeded;

void csprng_init(void) {
    /* Seed from kernel getrandom. */
    uint8_t seed[32];
    /* Call getrandom in 8-byte chunks (kernel limit is 256). */
    for (int i = 0; i < 32; i += 8) {
        uint64_t r = __telix_syscall2(SYS_GETRANDOM, (uint64_t)(uintptr_t)&seed[i], 8);
        (void)r;
    }
    memcpy(csprng_key, seed, 32);
    csprng_counter = 0;
    csprng_buf_pos = 64; /* Force refresh on first use. */
    csprng_seeded = 1;
}

void csprng_bytes(uint8_t *buf, size_t len) {
    if (!csprng_seeded) csprng_init();

    static const uint8_t nonce[12] = {0};
    size_t pos = 0;

    while (pos < len) {
        if (csprng_buf_pos >= 64) {
            chacha20_block(csprng_key, csprng_counter++, nonce, csprng_buf);
            csprng_buf_pos = 0;

            /* Re-key every 256 blocks for forward secrecy. */
            if ((csprng_counter & 0xFF) == 0) {
                uint8_t new_key[64];
                chacha20_block(csprng_key, csprng_counter++, nonce, new_key);
                memcpy(csprng_key, new_key, 32);
            }
        }
        size_t avail = 64 - csprng_buf_pos;
        size_t chunk = (len - pos < avail) ? (len - pos) : avail;
        memcpy(buf + pos, csprng_buf + csprng_buf_pos, chunk);
        csprng_buf_pos += chunk;
        pos += chunk;
    }
}
