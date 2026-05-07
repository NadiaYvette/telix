//! SipHash-2-4: keyed PRF used for cluster membership authentication
//! on discovery announcements and proxy_srv wire frames (Tier-5 piece D).
//!
//! Reference: <https://www.aumasson.jp/siphash/siphash.pdf>.
//! 16-byte key, arbitrary-length input, 64-bit digest.  Two compression
//! rounds per block, four finalization rounds — the standard
//! "SipHash-2-4" parameterisation.  Output is keyed and DoS-resistant
//! but not collision-resistant; the threat model is "is this peer in
//! my cluster?", not "did anyone tamper with this byte stream?".

#[inline]
fn rotl(x: u64, b: u32) -> u64 {
    x.rotate_left(b)
}

#[inline]
fn sipround(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = rotl(v[1], 13);
    v[1] ^= v[0];
    v[0] = rotl(v[0], 32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = rotl(v[3], 16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = rotl(v[3], 21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = rotl(v[1], 17);
    v[1] ^= v[2];
    v[2] = rotl(v[2], 32);
}

pub fn siphash_2_4(key: &[u8; 16], data: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let k1 = u64::from_le_bytes([
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
    ]);
    let mut v = [
        k0 ^ 0x736f6d6570736575,
        k1 ^ 0x646f72616e646f6d,
        k0 ^ 0x6c7967656e657261,
        k1 ^ 0x7465646279746573,
    ];
    let len = data.len();
    let blocks = len / 8;
    for i in 0..blocks {
        let off = i * 8;
        let m = u64::from_le_bytes([
            data[off], data[off + 1], data[off + 2], data[off + 3],
            data[off + 4], data[off + 5], data[off + 6], data[off + 7],
        ]);
        v[3] ^= m;
        sipround(&mut v);
        sipround(&mut v);
        v[0] ^= m;
    }
    // Trailing bytes + length tag in MSB.
    let mut last = (len as u64 & 0xff) << 56;
    let tail_off = blocks * 8;
    for i in tail_off..len {
        last |= (data[i] as u64) << ((i - tail_off) * 8);
    }
    v[3] ^= last;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= last;
    v[2] ^= 0xff;
    sipround(&mut v);
    sipround(&mut v);
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^ v[1] ^ v[2] ^ v[3]
}
