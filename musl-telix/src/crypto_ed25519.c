/* Ed25519 signatures - uses SHA-512 and Curve25519 field arithmetic.
 * Pure integer, no FP. Implements RFC 8032. */
#include <telix/crypto.h>
#include <string.h>

/* Field element: same representation as curve25519 (5 x 51-bit limbs). */
typedef uint64_t fe[5];
typedef unsigned __int128 u128;

/* -- Field operations (identical to curve25519) -- */

static void fe_frombytes(fe h, const uint8_t s[32]) {
    uint64_t lo=0, hi=0, mi1=0, mi2=0;
    for (int i=0;i<8;i++) lo |= (uint64_t)s[i] << (i*8);
    for (int i=0;i<8;i++) hi |= (uint64_t)s[8+i] << (i*8);
    for (int i=0;i<8;i++) mi1 |= (uint64_t)s[16+i] << (i*8);
    for (int i=0;i<8;i++) mi2 |= (uint64_t)s[24+i] << (i*8);
    h[0] = lo & 0x7ffffffffffff;
    h[1] = ((lo >> 51) | (hi << 13)) & 0x7ffffffffffff;
    h[2] = ((hi >> 38) | (mi1 << 26)) & 0x7ffffffffffff;
    h[3] = ((mi1 >> 25) | (mi2 << 39)) & 0x7ffffffffffff;
    h[4] = (mi2 >> 12) & 0x7ffffffffffff;
}

static void fe_tobytes(uint8_t s[32], const fe h) {
    uint64_t t[5];
    for (int i=0;i<5;i++) t[i]=h[i];
    uint64_t c;
    c=t[0]+19; c>>=51; c+=t[1]; c>>=51; c+=t[2]; c>>=51; c+=t[3]; c>>=51; c+=t[4]; c>>=51;
    t[0]+=19*c;
    c=t[0]>>51; t[0]&=0x7ffffffffffff; t[1]+=c;
    c=t[1]>>51; t[1]&=0x7ffffffffffff; t[2]+=c;
    c=t[2]>>51; t[2]&=0x7ffffffffffff; t[3]+=c;
    c=t[3]>>51; t[3]&=0x7ffffffffffff; t[4]+=c; t[4]&=0x7ffffffffffff;
    uint64_t w;
    w=t[0]|(t[1]<<51); for(int i=0;i<8;i++) s[i]=(uint8_t)(w>>(i*8));
    w=(t[1]>>13)|(t[2]<<38); for(int i=0;i<8;i++) s[8+i]=(uint8_t)(w>>(i*8));
    w=(t[2]>>26)|(t[3]<<25); for(int i=0;i<8;i++) s[16+i]=(uint8_t)(w>>(i*8));
    w=(t[3]>>39)|(t[4]<<12); for(int i=0;i<8;i++) s[24+i]=(uint8_t)(w>>(i*8));
}

static void fe_copy(fe h, const fe f) { for(int i=0;i<5;i++) h[i]=f[i]; }
static void fe_0(fe h) { for(int i=0;i<5;i++) h[i]=0; }
static void fe_1(fe h) { h[0]=1; for(int i=1;i<5;i++) h[i]=0; }

static void fe_add(fe h, const fe f, const fe g) {
    for(int i=0;i<5;i++) h[i]=f[i]+g[i];
}

static void fe_sub(fe h, const fe f, const fe g) {
    static const uint64_t bias[5]={0xfffffffffffda,0x7ffffffffffff,0x7ffffffffffff,0x7ffffffffffff,0x7ffffffffffff};
    for(int i=0;i<5;i++) h[i]=f[i]+bias[i]-g[i];
}

static void fe_mul(fe h, const fe f, const fe g) {
    uint64_t f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4];
    uint64_t g0=g[0],g1=g[1],g2=g[2],g3=g[3],g4=g[4];
    uint64_t g1_19=g1*19,g2_19=g2*19,g3_19=g3*19,g4_19=g4*19;
    u128 t0=(u128)f0*g0+(u128)f1*g4_19+(u128)f2*g3_19+(u128)f3*g2_19+(u128)f4*g1_19;
    u128 t1=(u128)f0*g1+(u128)f1*g0+(u128)f2*g4_19+(u128)f3*g3_19+(u128)f4*g2_19;
    u128 t2=(u128)f0*g2+(u128)f1*g1+(u128)f2*g0+(u128)f3*g4_19+(u128)f4*g3_19;
    u128 t3=(u128)f0*g3+(u128)f1*g2+(u128)f2*g1+(u128)f3*g0+(u128)f4*g4_19;
    u128 t4=(u128)f0*g4+(u128)f1*g3+(u128)f2*g2+(u128)f3*g1+(u128)f4*g0;
    uint64_t c;
    c=(uint64_t)(t0>>51); h[0]=(uint64_t)t0&0x7ffffffffffff; t1+=c;
    c=(uint64_t)(t1>>51); h[1]=(uint64_t)t1&0x7ffffffffffff; t2+=c;
    c=(uint64_t)(t2>>51); h[2]=(uint64_t)t2&0x7ffffffffffff; t3+=c;
    c=(uint64_t)(t3>>51); h[3]=(uint64_t)t3&0x7ffffffffffff; t4+=c;
    c=(uint64_t)(t4>>51); h[4]=(uint64_t)t4&0x7ffffffffffff;
    h[0]+=c*19; c=h[0]>>51; h[0]&=0x7ffffffffffff; h[1]+=c;
}

static void fe_sq(fe h, const fe f) { fe_mul(h,f,f); }

static void fe_invert(fe out, const fe z) {
    fe t0,t1,t2,t3; int i;
    fe_sq(t0,z); fe_sq(t1,t0); fe_sq(t1,t1);
    fe_mul(t1,z,t1); fe_mul(t0,t0,t1);
    fe_sq(t2,t0); fe_mul(t1,t1,t2);
    fe_sq(t2,t1); for(i=1;i<5;i++) fe_sq(t2,t2);
    fe_mul(t1,t2,t1);
    fe_sq(t2,t1); for(i=1;i<10;i++) fe_sq(t2,t2);
    fe_mul(t2,t2,t1);
    fe_sq(t3,t2); for(i=1;i<20;i++) fe_sq(t3,t3);
    fe_mul(t2,t3,t2);
    fe_sq(t2,t2); for(i=1;i<10;i++) fe_sq(t2,t2);
    fe_mul(t1,t2,t1);
    fe_sq(t2,t1); for(i=1;i<50;i++) fe_sq(t2,t2);
    fe_mul(t2,t2,t1);
    fe_sq(t3,t2); for(i=1;i<100;i++) fe_sq(t3,t3);
    fe_mul(t2,t3,t2);
    fe_sq(t2,t2); for(i=1;i<50;i++) fe_sq(t2,t2);
    fe_mul(t1,t2,t1);
    fe_sq(t1,t1); for(i=1;i<5;i++) fe_sq(t1,t1);
    fe_mul(out,t1,t0);
}

static void fe_neg(fe h, const fe f) {
    fe zero; fe_0(zero);
    fe_sub(h, zero, f);
}

/* fe_pow22523: compute z^((p-5)/8) = z^(2^252-3) */
static void fe_pow22523(fe out, const fe z) {
    fe t0,t1,t2; int i;
    fe_sq(t0,z); fe_sq(t1,t0); fe_sq(t1,t1);
    fe_mul(t1,z,t1); fe_mul(t0,t0,t1);
    fe_sq(t0,t0); fe_mul(t0,t1,t0);
    fe_sq(t1,t0); for(i=1;i<5;i++) fe_sq(t1,t1);
    fe_mul(t0,t1,t0);
    fe_sq(t1,t0); for(i=1;i<10;i++) fe_sq(t1,t1);
    fe_mul(t1,t1,t0);
    fe_sq(t2,t1); for(i=1;i<20;i++) fe_sq(t2,t2);
    fe_mul(t1,t2,t1);
    fe_sq(t1,t1); for(i=1;i<10;i++) fe_sq(t1,t1);
    fe_mul(t0,t1,t0);
    fe_sq(t1,t0); for(i=1;i<50;i++) fe_sq(t1,t1);
    fe_mul(t1,t1,t0);
    fe_sq(t2,t1); for(i=1;i<100;i++) fe_sq(t2,t2);
    fe_mul(t1,t2,t1);
    fe_sq(t1,t1); for(i=1;i<50;i++) fe_sq(t1,t1);
    fe_mul(t0,t1,t0);
    fe_sq(t0,t0); fe_sq(t0,t0);
    fe_mul(out,t0,z);
}

static int fe_isneg(const fe f) {
    uint8_t s[32]; fe_tobytes(s, f);
    return s[0] & 1;
}

static int fe_isnonzero(const fe f) {
    uint8_t s[32]; fe_tobytes(s, f);
    uint8_t r = 0;
    for (int i=0;i<32;i++) r |= s[i];
    return r != 0;
}

/* -- Extended coordinates point (X:Y:Z:T where x=X/Z, y=Y/Z, T=X*Y/Z) -- */
typedef struct { fe X, Y, Z, T; } ge_p3;
typedef struct { fe X, Y, Z; } ge_p2;
typedef struct { fe X, Y, Z, T; } ge_p1p1;
typedef struct { fe yplusx, yminusx, xy2d; } ge_precomp;
typedef struct { fe YplusX, YminusX, Z, T2d; } ge_cached;

/* d = -121665/121666 mod p */
static const uint8_t d_bytes[32] = {
    0xa3,0x78,0x59,0x13,0xca,0x4d,0xeb,0x75,0xab,0xd1,0x68,0x2b,0xc5,0x29,0x04,0x4b,
    0x6c,0x17,0xab,0xf2,0xb4,0x6e,0x28,0x9b,0xe2,0xaa,0x68,0xc0,0x00,0x00,0x00,0x10
};

/* 2*d */
static const uint8_t d2_bytes[32] = {
    0x45,0xf1,0xb2,0x26,0x94,0x9b,0xd6,0xeb,0x56,0xa3,0xd1,0x56,0x8b,0x52,0x09,0x96,
    0xd8,0x49,0x1d,0x65,0x69,0xdd,0x50,0x36,0xc5,0x55,0xd1,0x01,0x00,0x00,0x00,0x20
};

/* sqrt(-1) mod p */
static const uint8_t sqrtm1_bytes[32] = {
    0xb0,0xa0,0x0e,0x4a,0x27,0x1b,0xee,0xc4,0x78,0xe4,0x2f,0xad,0x06,0x18,0x43,0x2f,
    0xa7,0xd7,0xfb,0x3d,0x99,0x00,0x4d,0x2b,0x0b,0xdf,0x63,0x26,0x00,0x00,0x00,0x21
};

static fe d_fe, d2_fe, sqrtm1_fe;
static int ge_inited = 0;

static void ge_init_consts(void) {
    if (ge_inited) return;
    fe_frombytes(d_fe, d_bytes);
    fe_frombytes(d2_fe, d2_bytes);
    fe_frombytes(sqrtm1_fe, sqrtm1_bytes);
    ge_inited = 1;
}

static void ge_p3_0(ge_p3 *p) {
    fe_0(p->X); fe_1(p->Y); fe_1(p->Z); fe_0(p->T);
}

static void ge_p3_to_p2(ge_p2 *r, const ge_p3 *p) {
    fe_copy(r->X, p->X); fe_copy(r->Y, p->Y); fe_copy(r->Z, p->Z);
}

static void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p) {
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
    fe_mul(r->T, p->X, p->Y);
}

static void ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p) {
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
}

static void ge_p3_to_cached(ge_cached *r, const ge_p3 *p) {
    fe_add(r->YplusX, p->Y, p->X);
    fe_sub(r->YminusX, p->Y, p->X);
    fe_copy(r->Z, p->Z);
    fe_mul(r->T2d, p->T, d2_fe);
}

/* p3 + cached -> p1p1 */
static void ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q) {
    fe t0;
    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(r->Z, r->X, q->YplusX);
    fe_mul(r->Y, r->Y, q->YminusX);
    fe_mul(r->T, q->T2d, p->T);
    fe_mul(r->X, p->Z, q->Z);
    fe_add(t0, r->X, r->X);
    fe_sub(r->X, r->Z, r->Y);
    fe_add(r->Y, r->Z, r->Y);
    fe_add(r->Z, t0, r->T);
    fe_sub(r->T, t0, r->T);
}

/* p2 double -> p1p1 */
static void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p) {
    fe t0;
    fe_sq(r->X, p->X);
    fe_sq(r->Z, p->Y);
    fe_sq(r->T, p->Z);
    fe_add(r->T, r->T, r->T);
    fe_add(r->Y, p->X, p->Y);
    fe_sq(t0, r->Y);
    fe_add(r->Y, r->Z, r->X);
    fe_sub(r->Z, r->Z, r->X);
    fe_sub(r->X, t0, r->Y);
    fe_sub(r->T, r->T, r->Z);
}

/* Encode point to 32 bytes. */
static void ge_p3_tobytes(uint8_t s[32], const ge_p3 *p) {
    fe recip, x, y;
    fe_invert(recip, p->Z);
    fe_mul(x, p->X, recip);
    fe_mul(y, p->Y, recip);
    fe_tobytes(s, y);
    s[31] ^= fe_isneg(x) << 7;
}

/* Decode point from 32 bytes. Returns 0 on success. */
static int ge_frombytes(ge_p3 *p, const uint8_t s[32]) {
    ge_init_consts();
    fe u, v, v3, vxx, check;

    fe_frombytes(p->Y, s);
    fe_1(p->Z);
    fe_sq(u, p->Y);         /* u = y^2 */
    fe_mul(v, u, d_fe);     /* v = d*y^2 */
    fe_sub(u, u, p->Z);     /* u = y^2 - 1 */
    fe_add(v, v, p->Z);     /* v = d*y^2 + 1 */

    fe_sq(v3, v);
    fe_mul(v3, v3, v);       /* v3 = v^3 */
    fe_sq(p->X, v3);
    fe_mul(p->X, p->X, v);  /* x = v^7 */
    fe_mul(p->X, p->X, u);  /* x = u*v^7 */

    fe_pow22523(p->X, p->X); /* x = (u*v^7)^((p-5)/8) */
    fe_mul(p->X, p->X, v3);
    fe_mul(p->X, p->X, u);   /* x = u*v^3 * (u*v^7)^((p-5)/8) */

    fe_sq(vxx, p->X);
    fe_mul(vxx, vxx, v);
    fe_sub(check, vxx, u);
    if (fe_isnonzero(check)) {
        fe_add(check, vxx, u);
        if (fe_isnonzero(check)) return -1;
        fe_mul(p->X, p->X, sqrtm1_fe);
    }

    if (fe_isneg(p->X) != (s[31] >> 7)) {
        fe_neg(p->X, p->X);
    }

    fe_mul(p->T, p->X, p->Y);
    return 0;
}

/* Scalar multiplication: result = scalar * base_point.
 * Uses a simple double-and-add. */
static void ge_scalarmult_base(ge_p3 *r, const uint8_t scalar[32]) {
    /* Base point B for Ed25519. */
    static const uint8_t B_bytes[32] = {
        0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
    };
    ge_p3 B;
    ge_frombytes(&B, B_bytes);

    ge_p3_0(r);

    for (int i = 255; i >= 0; i--) {
        ge_p2 p2;
        ge_p1p1 p1;
        ge_p3_to_p2(&p2, r);
        ge_p2_dbl(&p1, &p2);
        ge_p1p1_to_p3(r, &p1);

        if ((scalar[i/8] >> (i&7)) & 1) {
            ge_cached bc;
            ge_p3_to_cached(&bc, &B);
            ge_add(&p1, r, &bc);
            ge_p1p1_to_p3(r, &p1);
        }
    }
}

/* Scalar multiplication: result = scalar * point. */
static void ge_scalarmult(ge_p3 *r, const uint8_t scalar[32], const ge_p3 *point) {
    ge_p3_0(r);

    for (int i = 255; i >= 0; i--) {
        ge_p2 p2;
        ge_p1p1 p1;
        ge_p3_to_p2(&p2, r);
        ge_p2_dbl(&p1, &p2);
        ge_p1p1_to_p3(r, &p1);

        if ((scalar[i/8] >> (i&7)) & 1) {
            ge_cached qc;
            ge_p3_to_cached(&qc, point);
            ge_add(&p1, r, &qc);
            ge_p1p1_to_p3(r, &p1);
        }
    }
}

/* -- Scalar arithmetic mod L (group order) -- */
/* L = 2^252 + 27742317777372353535851937790883648493 */

/* Reduce a 64-byte (512-bit) scalar mod L.
 * We use a simple schoolbook approach with 32-bit limbs. */
static void sc_reduce(uint8_t out[32], const uint8_t in[64]) {
    /* For simplicity, we do Barrett reduction using 64-bit arithmetic.
     * This is adequate for our use case. */
    /* The order L in little-endian bytes: */
    static const uint8_t L[32] = {
        0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10
    };

    /* Simple reduction: interpret input as 512-bit LE integer, reduce mod L.
     * We use the fact that 2^256 mod L is small. */

    /* Load as 32 uint16_t limbs (covers 512 bits). */
    int64_t a[64];
    for (int i=0;i<64;i++) a[i] = in[i];

    /* Multiply-and-subtract approach: reduce from top.
     * L ~= 2^252, so each subtraction of L*2^(8*i) reduces by ~252 bits.
     * For 512 bits, we need multiple rounds. */

    /* Schoolbook reduction using signed digits. */
    /* This is a simplified version - we subtract multiples of L. */

    /* Actually, let's just use a direct multi-precision modular reduction.
     * Load as 64-byte number, repeatedly subtract L if >= L. */
    /* For production this would be slow, but for our SSH use case it's fine. */

    /* Convert to 32-bit limbs for easier arithmetic. */
    uint32_t s[16]; /* 512 bits in 16 x 32-bit limbs */
    for (int i=0;i<16;i++)
        s[i] = (uint32_t)in[i*4] | ((uint32_t)in[i*4+1]<<8) |
               ((uint32_t)in[i*4+2]<<16) | ((uint32_t)in[i*4+3]<<24);

    /* l in 32-bit limbs */
    uint32_t l[8];
    for (int i=0;i<8;i++)
        l[i] = (uint32_t)L[i*4] | ((uint32_t)L[i*4+1]<<8) |
               ((uint32_t)L[i*4+2]<<16) | ((uint32_t)L[i*4+3]<<24);

    /* Reduce: compute s mod l using schoolbook long division approach.
     * Process from the top 256 bits down. */
    /* s = s_hi * 2^256 + s_lo. We need (s_hi * (2^256 mod l) + s_lo) mod l. */
    /* 2^256 mod l = 2^256 - l = -l mod 2^256... actually:
     * 2^252 = l - c where c = 27742317777372353535851937790883648493
     * So 2^256 = 16 * 2^252 = 16*(l-c) = 16*l - 16*c
     * 2^256 mod l = -16*c mod l = l - 16*c
     * This is complex. Let's just use a simpler iterative subtraction approach. */

    /* For a research OS, Barrett reduction overkill. Just do repeated subtraction.
     * First reduce to 256 bits, then subtract L until < L. */

    /* r = 2^256 mod L (precomputed): */
    static const uint8_t r256[32] = {
        0x1c,0x95,0x98,0x8d,0x73,0x57,0x9e,0x4b,0x53,0xc6,0x11,0xb8,0x42,0x12,0x42,0xd6,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x0f
    };

    /* s_hi = s[8..15], s_lo = s[0..7] */
    /* result = (s_hi * r256 + s_lo) mod L */
    /* Compute s_hi * r256 as 512-bit product, then add s_lo, then reduce. */
    /* This is getting complex. For simplicity, use the reference implementation's
     * approach: just output the input with carries propagated mod L. */

    (void)a; (void)s; (void)l; (void)r256;

    /* Use 64-bit limb approach. */
    /* Load full 512-bit value into 8 x 64-bit limbs. */
    uint64_t v[8];
    for (int i=0;i<8;i++) {
        v[i] = (uint64_t)in[i*8] | ((uint64_t)in[i*8+1]<<8) |
               ((uint64_t)in[i*8+2]<<16) | ((uint64_t)in[i*8+3]<<24) |
               ((uint64_t)in[i*8+4]<<32) | ((uint64_t)in[i*8+5]<<40) |
               ((uint64_t)in[i*8+6]<<48) | ((uint64_t)in[i*8+7]<<56);
    }

    /* L in 64-bit limbs: */
    static const uint64_t Lv[4] = {
        0x5812631a5cf5d3edULL, 0x14def9dea2f79cd6ULL, 0x0000000000000000ULL, 0x1000000000000000ULL
    };

    /* Reduce: fold v[4..7] using 2^256 mod L, iteratively. */
    /* 2^256 mod L = 0x0ffffffffffffffffffffffffffffffec6ef5bf4737dcf70d6ec31748d98951d */
    static const uint64_t m[4] = {
        0xd6ec31748d98951dULL, 0xc6ef5bf4737dcf70ULL, 0xffffffffffffffffULL, 0x0fffffffffffffffULL
    };

    /* result = v_lo + v_hi * m, where v_lo = v[0..3], v_hi = v[4..7] */
    /* This can overflow to 320 bits, so we need to handle carries. */
    /* For simplicity, do it in two rounds. */

    /* Round 1: fold v[4..7] * m into accumulator. */
    u128 acc[5] = {0,0,0,0,0};
    for (int i=0;i<4;i++) acc[i] = v[i]; /* Start with v_lo. */

    for (int i=0;i<4;i++) {
        for (int j=0;j<4;j++) {
            int k = i+j;
            acc[k] += (u128)v[4+i] * m[j];
        }
    }

    /* Propagate carries. */
    for (int i=0;i<4;i++) {
        acc[i+1] += (uint64_t)(acc[i] >> 64);
        acc[i] = (uint64_t)acc[i];
    }
    /* acc[4] might be nonzero - need another round of folding. */
    uint64_t hi = (uint64_t)acc[4];
    /* Fold hi * m into acc[0..3]. */
    u128 carry = 0;
    for (int i=0;i<4;i++) {
        carry += (uint64_t)acc[i] + (u128)hi * m[i];
        acc[i] = (uint64_t)carry;
        carry >>= 64;
    }
    /* carry should be small enough now. One more fold if needed. */
    hi = (uint64_t)carry;
    if (hi) {
        carry = 0;
        for (int i=0;i<4;i++) {
            carry += (uint64_t)acc[i] + (u128)hi * m[i];
            acc[i] = (uint64_t)carry;
            carry >>= 64;
        }
    }

    /* Now acc[0..3] is at most ~2*L. Subtract L if >= L. */
    uint64_t r[4];
    for (int i=0;i<4;i++) r[i] = (uint64_t)acc[i];

    /* Try subtracting L. */
    int64_t borrow = 0;
    uint64_t t[4];
    for (int i=0;i<4;i++) {
        int64_t diff = (int64_t)r[i] - (int64_t)Lv[i] + borrow;
        t[i] = (uint64_t)diff;
        borrow = diff >> 63; /* -1 if borrowed, 0 otherwise */
    }

    /* If no borrow, use t (result was >= L). Otherwise keep r. */
    uint64_t mask = (uint64_t)borrow; /* 0xFFFF... if r < L, 0 if r >= L */
    for (int i=0;i<4;i++) r[i] = (r[i] & mask) | (t[i] & ~mask);

    /* Try subtracting L again (could be 2L < result < 3L after fold). */
    borrow = 0;
    for (int i=0;i<4;i++) {
        int64_t diff = (int64_t)r[i] - (int64_t)Lv[i] + borrow;
        t[i] = (uint64_t)diff;
        borrow = diff >> 63;
    }
    mask = (uint64_t)borrow;
    for (int i=0;i<4;i++) r[i] = (r[i] & mask) | (t[i] & ~mask);

    /* Store result. */
    for (int i=0;i<4;i++) {
        out[i*8+0] = (uint8_t)(r[i]);       out[i*8+1] = (uint8_t)(r[i]>>8);
        out[i*8+2] = (uint8_t)(r[i]>>16);   out[i*8+3] = (uint8_t)(r[i]>>24);
        out[i*8+4] = (uint8_t)(r[i]>>32);   out[i*8+5] = (uint8_t)(r[i]>>40);
        out[i*8+6] = (uint8_t)(r[i]>>48);   out[i*8+7] = (uint8_t)(r[i]>>56);
    }
}

/* sc_muladd: out = a*b + c mod L */
static void sc_muladd(uint8_t out[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32]) {
    /* Load a, b, c as 4 x 64-bit limbs. */
    uint64_t av[4], bv[4], cv[4];
    for (int i=0;i<4;i++) {
        av[i] = bv[i] = cv[i] = 0;
        for (int j=0;j<8;j++) {
            av[i] |= (uint64_t)a[i*8+j] << (j*8);
            bv[i] |= (uint64_t)b[i*8+j] << (j*8);
            cv[i] |= (uint64_t)c[i*8+j] << (j*8);
        }
    }

    /* Compute a*b as 512-bit product. */
    u128 prod[8];
    for (int i=0;i<8;i++) prod[i]=0;
    for (int i=0;i<4;i++)
        for (int j=0;j<4;j++)
            prod[i+j] += (u128)av[i] * bv[j];

    /* Propagate carries to get 8 x 64-bit limbs. */
    uint64_t pv[8];
    u128 carry = 0;
    for (int i=0;i<8;i++) {
        prod[i] += carry;
        pv[i] = (uint64_t)prod[i];
        carry = prod[i] >> 64;
    }

    /* Add c. */
    carry = 0;
    for (int i=0;i<4;i++) {
        carry += (u128)pv[i] + cv[i];
        pv[i] = (uint64_t)carry;
        carry >>= 64;
    }
    for (int i=4;i<8;i++) {
        carry += pv[i];
        pv[i] = (uint64_t)carry;
        carry >>= 64;
    }

    /* Pack into 64 bytes and reduce. */
    uint8_t buf[64];
    for (int i=0;i<8;i++)
        for (int j=0;j<8;j++)
            buf[i*8+j] = (uint8_t)(pv[i] >> (j*8));

    sc_reduce(out, buf);
}

/* -- Ed25519 API -- */

void ed25519_create_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]) {
    ge_init_consts();

    /* sk = SHA-512(seed) */
    uint8_t h[64];
    sha512(seed, 32, h);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;

    /* A = h[0..31] * B */
    ge_p3 A;
    ge_scalarmult_base(&A, h);
    ge_p3_tobytes(pk, &A);

    /* sk = seed || pk */
    memcpy(sk, seed, 32);
    memcpy(sk+32, pk, 32);
}

void ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                  const uint8_t pk[32], const uint8_t sk[64]) {
    ge_init_consts();

    uint8_t az[64];
    sha512(sk, 32, az);  /* Hash seed part of sk. */
    az[0] &= 248;
    az[31] &= 127;
    az[31] |= 64;

    /* r = SHA-512(az[32..63] || msg) mod L */
    sha512_ctx hctx;
    sha512_init(&hctx);
    sha512_update(&hctx, az+32, 32);
    sha512_update(&hctx, msg, msg_len);
    uint8_t nonce[64];
    sha512_final(&hctx, nonce);

    uint8_t r_scalar[32];
    sc_reduce(r_scalar, nonce);

    /* R = r * B */
    ge_p3 R;
    ge_scalarmult_base(&R, r_scalar);
    ge_p3_tobytes(sig, &R); /* First 32 bytes of sig = R */

    /* k = SHA-512(R || pk || msg) mod L */
    sha512_init(&hctx);
    sha512_update(&hctx, sig, 32);
    sha512_update(&hctx, pk, 32);
    sha512_update(&hctx, msg, msg_len);
    uint8_t hram[64];
    sha512_final(&hctx, hram);

    uint8_t k[32];
    sc_reduce(k, hram);

    /* S = r + k*az[0..31] mod L */
    sc_muladd(sig+32, k, az, r_scalar);
}

int ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                   const uint8_t pk[32]) {
    ge_init_consts();

    /* Check S < L */
    static const uint8_t Lbytes[32] = {
        0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10
    };
    for (int i=31;i>=0;i--) {
        if (sig[32+i] < Lbytes[i]) break;
        if (sig[32+i] > Lbytes[i]) return -1;
    }

    /* Decode A = -pk */
    ge_p3 A;
    if (ge_frombytes(&A, pk) != 0) return -1;

    /* k = SHA-512(R || pk || msg) */
    sha512_ctx hctx;
    sha512_init(&hctx);
    sha512_update(&hctx, sig, 32);
    sha512_update(&hctx, pk, 32);
    sha512_update(&hctx, msg, msg_len);
    uint8_t hram[64];
    sha512_final(&hctx, hram);
    uint8_t k[32];
    sc_reduce(k, hram);

    /* Check: S*B == R + k*A */
    /* Compute S*B */
    ge_p3 sb;
    ge_scalarmult_base(&sb, sig+32);

    /* Compute k*A */
    ge_p3 ka;
    ge_scalarmult(&ka, k, &A);

    /* Decode R */
    ge_p3 R;
    if (ge_frombytes(&R, sig) != 0) return -1;

    /* Check sb == R + ka */
    /* R + ka: */
    ge_cached kac;
    ge_p3_to_cached(&kac, &ka);
    ge_p1p1 sum;
    ge_add(&sum, &R, &kac);
    ge_p3 check;
    ge_p1p1_to_p3(&check, &sum);

    /* Compare sb and check by encoding both. */
    uint8_t sb_bytes[32], check_bytes[32];
    ge_p3_tobytes(sb_bytes, &sb);
    ge_p3_tobytes(check_bytes, &check);

    uint8_t diff = 0;
    for (int i=0;i<32;i++) diff |= sb_bytes[i] ^ check_bytes[i];
    return diff ? -1 : 0;
}
