/* X25519 (Curve25519 ECDH) - donna-c64 style, pure integer, no FP.
 * Uses 5 x 51-bit limbs in uint64_t with __uint128_t for multiplication. */
#include <telix/crypto.h>
#include <string.h>

typedef uint64_t fe[5];  /* Field element: 5 limbs, each < 2^51 */
typedef unsigned __int128 u128;

static void fe_frombytes(fe h, const uint8_t s[32]) {
    uint64_t t[5];
    uint64_t lo = 0, hi = 0, mi1 = 0, mi2 = 0;
    for (int i=0;i<8;i++) lo |= (uint64_t)s[i] << (i*8);
    for (int i=0;i<8;i++) hi |= (uint64_t)s[8+i] << (i*8);
    for (int i=0;i<8;i++) mi1 |= (uint64_t)s[16+i] << (i*8);
    for (int i=0;i<8;i++) mi2 |= (uint64_t)s[24+i] << (i*8);

    t[0] = lo & 0x7ffffffffffff;                          /* bits 0..50 */
    t[1] = ((lo >> 51) | (hi << 13)) & 0x7ffffffffffff;   /* bits 51..101 */
    t[2] = ((hi >> 38) | (mi1 << 26)) & 0x7ffffffffffff;  /* bits 102..152 */
    t[3] = ((mi1 >> 25) | (mi2 << 39)) & 0x7ffffffffffff; /* bits 153..203 */
    t[4] = (mi2 >> 12) & 0x7ffffffffffff;                 /* bits 204..254 */

    for (int i=0;i<5;i++) h[i]=t[i];
}

static void fe_tobytes(uint8_t s[32], const fe h) {
    uint64_t t[5];
    for (int i=0;i<5;i++) t[i]=h[i];

    /* Reduce modulo p = 2^255-19. */
    uint64_t c;
    c = t[0] + 19; c >>= 51;
    c += t[1]; c >>= 51;
    c += t[2]; c >>= 51;
    c += t[3]; c >>= 51;
    c += t[4]; c >>= 51; /* c is 0 or 1 */

    t[0] += 19 * c;
    c = t[0] >> 51; t[0] &= 0x7ffffffffffff;
    t[1] += c; c = t[1] >> 51; t[1] &= 0x7ffffffffffff;
    t[2] += c; c = t[2] >> 51; t[2] &= 0x7ffffffffffff;
    t[3] += c; c = t[3] >> 51; t[3] &= 0x7ffffffffffff;
    t[4] += c; t[4] &= 0x7ffffffffffff;

    /* Pack into bytes. */
    uint64_t w;
    w = t[0] | (t[1] << 51);
    for (int i=0;i<8;i++) s[i] = (uint8_t)(w >> (i*8));
    w = (t[1] >> 13) | (t[2] << 38);
    for (int i=0;i<8;i++) s[8+i] = (uint8_t)(w >> (i*8));
    w = (t[2] >> 26) | (t[3] << 25);
    for (int i=0;i<8;i++) s[16+i] = (uint8_t)(w >> (i*8));
    w = (t[3] >> 39) | (t[4] << 12);
    for (int i=0;i<8;i++) s[24+i] = (uint8_t)(w >> (i*8));
}

static void fe_copy(fe h, const fe f) {
    for (int i=0;i<5;i++) h[i]=f[i];
}

static void fe_0(fe h) { for (int i=0;i<5;i++) h[i]=0; }
static void fe_1(fe h) { h[0]=1; for (int i=1;i<5;i++) h[i]=0; }

static void fe_add(fe h, const fe f, const fe g) {
    for (int i=0;i<5;i++) h[i]=f[i]+g[i];
}

static void fe_sub(fe h, const fe f, const fe g) {
    /* Add 2*p to avoid underflow. */
    static const uint64_t bias[5] = {
        0xfffffffffffda, 0x7ffffffffffff, 0x7ffffffffffff,
        0x7ffffffffffff, 0x7ffffffffffff
    };
    for (int i=0;i<5;i++) h[i]=f[i]+bias[i]-g[i];
}

static void fe_mul(fe h, const fe f, const fe g) {
    u128 t[5];
    uint64_t f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4];
    uint64_t g0=g[0],g1=g[1],g2=g[2],g3=g[3],g4=g[4];
    uint64_t g1_19=g1*19, g2_19=g2*19, g3_19=g3*19, g4_19=g4*19;

    t[0] = (u128)f0*g0 + (u128)f1*g4_19 + (u128)f2*g3_19 + (u128)f3*g2_19 + (u128)f4*g1_19;
    t[1] = (u128)f0*g1 + (u128)f1*g0    + (u128)f2*g4_19 + (u128)f3*g3_19 + (u128)f4*g2_19;
    t[2] = (u128)f0*g2 + (u128)f1*g1    + (u128)f2*g0    + (u128)f3*g4_19 + (u128)f4*g3_19;
    t[3] = (u128)f0*g3 + (u128)f1*g2    + (u128)f2*g1    + (u128)f3*g0    + (u128)f4*g4_19;
    t[4] = (u128)f0*g4 + (u128)f1*g3    + (u128)f2*g2    + (u128)f3*g1    + (u128)f4*g0;

    uint64_t c;
    c = (uint64_t)(t[0] >> 51); h[0] = (uint64_t)t[0] & 0x7ffffffffffff; t[1] += c;
    c = (uint64_t)(t[1] >> 51); h[1] = (uint64_t)t[1] & 0x7ffffffffffff; t[2] += c;
    c = (uint64_t)(t[2] >> 51); h[2] = (uint64_t)t[2] & 0x7ffffffffffff; t[3] += c;
    c = (uint64_t)(t[3] >> 51); h[3] = (uint64_t)t[3] & 0x7ffffffffffff; t[4] += c;
    c = (uint64_t)(t[4] >> 51); h[4] = (uint64_t)t[4] & 0x7ffffffffffff;
    h[0] += c * 19;
    c = h[0] >> 51; h[0] &= 0x7ffffffffffff; h[1] += c;
}

static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

static void fe_mul_scalar(fe h, const fe f, uint64_t n) {
    u128 c = 0;
    for (int i=0;i<5;i++) {
        c += (u128)f[i] * n;
        h[i] = (uint64_t)c & 0x7ffffffffffff;
        c >>= 51;
    }
    h[0] += (uint64_t)c * 19;
    uint64_t carry = h[0] >> 51; h[0] &= 0x7ffffffffffff; h[1] += carry;
}

static void fe_invert(fe out, const fe z) {
    fe t0, t1, t2, t3;
    int i;

    fe_sq(t0, z);
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sq(t2, t1);
    for (i=1;i<5;i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (i=1;i<10;i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (i=1;i<20;i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (i=1;i<10;i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (i=1;i<50;i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (i=1;i<100;i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (i=1;i<50;i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i=1;i<5;i++) fe_sq(t1, t1);
    fe_mul(out, t1, t0);
}

/* Conditional swap: swap f and g if b == 1, noop if b == 0. */
static void fe_cswap(fe f, fe g, uint64_t b) {
    uint64_t mask = -(uint64_t)b;
    for (int i=0;i<5;i++) {
        uint64_t x = (f[i] ^ g[i]) & mask;
        f[i] ^= x;
        g[i] ^= x;
    }
}

/* Montgomery ladder scalar multiplication. */
void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    fe_frombytes(x1, point);
    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    uint64_t swap = 0;
    for (int pos = 254; pos >= 0; pos--) {
        uint64_t b = (e[pos/8] >> (pos&7)) & 1;
        fe_cswap(x2, x3, swap ^ b);
        fe_cswap(z2, z3, swap ^ b);
        swap = b;

        fe_sub(tmp0, x3, z3);
        fe_sub(tmp1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, tmp0, x2);
        fe_mul(z2, z2, tmp1);
        fe_sq(tmp0, tmp1);
        fe_sq(tmp1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, tmp1, tmp0);
        fe_sub(tmp1, tmp1, tmp0);
        fe_sq(z2, z2);
        fe_mul_scalar(z3, tmp1, 121666);
        fe_sq(x3, x3);
        fe_add(tmp0, tmp0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, tmp1, tmp0);
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);
}

/* Base point for Curve25519: 9 */
static const uint8_t basepoint[32] = {9};

void x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
    x25519(out, scalar, basepoint);
}
