// ── SHA-256 ──
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256(data: Uint8Array): Uint8Array {
  let a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
  let e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

  const len = data.length;
  const bits = len * 8;
  // ceil((len + 9) / 64) via bit-shift: (len + 9 + 63) >> 6
  const totalLen = ((len + 72) >> 6) << 6;
  const padded = new Uint8Array(totalLen);
  padded.set(data);
  padded[len] = 0x80;

  const lo = bits >>> 0;
  const hi = (bits / 0x100000000) | 0;
  padded[totalLen - 8] = (hi >>> 24) & 0xff;
  padded[totalLen - 7] = (hi >>> 16) & 0xff;
  padded[totalLen - 6] = (hi >>> 8) & 0xff;
  padded[totalLen - 5] = hi & 0xff;
  padded[totalLen - 4] = (lo >>> 24) & 0xff;
  padded[totalLen - 3] = (lo >>> 16) & 0xff;
  padded[totalLen - 2] = (lo >>> 8) & 0xff;
  padded[totalLen - 1] = lo & 0xff;

  const W = new Uint32Array(64);

  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let t = 0; t < 16; t++) {
      const i = offset + (t << 2);
      W[t] = (padded[i] << 24) | (padded[i + 1] << 16) | (padded[i + 2] << 8) | padded[i + 3];
    }
    for (let t = 16; t < 64; t++) {
      const w15 = W[t - 15];
      const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
      const w2 = W[t - 2];
      const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
    }

    let va = a, vb = b, vc = c, vd = d, ve = e, vf = f, vg = g, vh = h;

    for (let t = 0; t < 64; t++) {
      const S1 = ((ve >>> 6) | (ve << 26)) ^ ((ve >>> 11) | (ve << 21)) ^ ((ve >>> 25) | (ve << 7));
      const ch = (ve & vf) ^ (~ve & vg);
      const temp1 = (vh + S1 + ch + K256[t] + W[t]) | 0;
      const S0 = ((va >>> 2) | (va << 30)) ^ ((va >>> 13) | (va << 19)) ^ ((va >>> 22) | (va << 10));
      const maj = (va & vb) ^ (va & vc) ^ (vb & vc);
      const temp2 = (S0 + maj) | 0;

      vh = vg; vg = vf; vf = ve; ve = (vd + temp1) | 0;
      vd = vc; vc = vb; vb = va; va = (temp1 + temp2) | 0;
    }

    a = (a + va) | 0; b = (b + vb) | 0; c = (c + vc) | 0; d = (d + vd) | 0;
    e = (e + ve) | 0; f = (f + vf) | 0; g = (g + vg) | 0; h = (h + vh) | 0;
  }

  const out = new Uint8Array(32);
  out[0]  = (a >>> 24) & 0xff; out[1]  = (a >>> 16) & 0xff; out[2]  = (a >>> 8) & 0xff; out[3]  = a & 0xff;
  out[4]  = (b >>> 24) & 0xff; out[5]  = (b >>> 16) & 0xff; out[6]  = (b >>> 8) & 0xff; out[7]  = b & 0xff;
  out[8]  = (c >>> 24) & 0xff; out[9]  = (c >>> 16) & 0xff; out[10] = (c >>> 8) & 0xff; out[11] = c & 0xff;
  out[12] = (d >>> 24) & 0xff; out[13] = (d >>> 16) & 0xff; out[14] = (d >>> 8) & 0xff; out[15] = d & 0xff;
  out[16] = (e >>> 24) & 0xff; out[17] = (e >>> 16) & 0xff; out[18] = (e >>> 8) & 0xff; out[19] = e & 0xff;
  out[20] = (f >>> 24) & 0xff; out[21] = (f >>> 16) & 0xff; out[22] = (f >>> 8) & 0xff; out[23] = f & 0xff;
  out[24] = (g >>> 24) & 0xff; out[25] = (g >>> 16) & 0xff; out[26] = (g >>> 8) & 0xff; out[27] = g & 0xff;
  out[28] = (h >>> 24) & 0xff; out[29] = (h >>> 16) & 0xff; out[30] = (h >>> 8) & 0xff; out[31] = h & 0xff;
  return out;
}

// ── SHA-512 / SHA-384 (zero BigInt, pure 32-bit ops) ──
const K512_hi = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  0xca273ece, 0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5, 0x113f9804, 0x1b710b35,
  0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 0x431d67c4, 0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c,
]);

const K512_lo = new Uint32Array([
  0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc, 0xf348b538, 0xb605d019, 0xaf194f9b, 0xda6d8118,
  0xa3030242, 0x45706fbe, 0x4ee4b28c, 0xd5ffb4e2, 0xf27b896f, 0x3b1696b1, 0x25c71235, 0xcf692694,
  0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65, 0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5,
  0xee66dfab, 0x2db43210, 0x98fb213f, 0xbeef0ee4, 0x3da88fc2, 0x930aa725, 0xe003826f, 0x0a0e6e70,
  0x46d22ffc, 0x5c26c926, 0x5ac42aed, 0x9d95b3df, 0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
  0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30, 0xd6ef5218, 0x5565a910, 0x5771202a, 0x32bbd1b8,
  0xb8d2d0c8, 0x5141ab53, 0xdf8eeb99, 0xe19b48a8, 0xc5c95a63, 0xe3418acb, 0x7763e373, 0xd6b2b8a3,
  0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec, 0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b,
  0xea26619c, 0x21c0c207, 0xcde0eb1e, 0xee6ed178, 0x72176fba, 0xa2c898a6, 0xbef90dae, 0x131c471b,
  0x23047d84, 0x40c72493, 0x15c9bebc, 0x9c100d4c, 0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817,
]);

const SHA512_INITIAL = [
  0x6a09e667, 0xf3bcc908,
  0xbb67ae85, 0x84caa73b,
  0x3c6ef372, 0xfe94f82b,
  0xa54ff53a, 0x5f1d36f1,
  0x510e527f, 0xade682d1,
  0x9b05688c, 0x2b3e6c1f,
  0x1f83d9ab, 0xfb41bd6b,
  0x5be0cd19, 0x137e2179,
] as const;

const SHA384_INITIAL = [
  0xcbbb9d5d, 0xc1059ed8,
  0x629a292a, 0x367cd507,
  0x9159015a, 0x3070dd17,
  0x152fecd8, 0xf70e5939,
  0x67332667, 0xffc00b31,
  0x8eb44a87, 0x68581511,
  0xdb0c2e0d, 0x64f98fa7,
  0x47b5481d, 0xbefa4fa4,
] as const;

function sha512Digest32(data: Uint8Array, initial: readonly number[], outBytes: 48 | 64): Uint8Array {
  let H0_hi = initial[0], H0_lo = initial[1];
  let H1_hi = initial[2], H1_lo = initial[3];
  let H2_hi = initial[4], H2_lo = initial[5];
  let H3_hi = initial[6], H3_lo = initial[7];
  let H4_hi = initial[8], H4_lo = initial[9];
  let H5_hi = initial[10], H5_lo = initial[11];
  let H6_hi = initial[12], H6_lo = initial[13];
  let H7_hi = initial[14], H7_lo = initial[15];

  const len = data.length;
  const bits = len * 8;
  // ceil((len + 17) / 128) via bit-shift: (len + 17 + 127) >> 7
  const totalLen = ((len + 144) >> 7) << 7;
  const padded = new Uint8Array(totalLen);
  padded.set(data);
  padded[len] = 0x80;
  // Uint8Array is zero-initialized, so the high 64 bits of the 128-bit length are already 0.
  // Write the low 64 bits (big-endian) at the very end.
  let b = bits;
  for (let i = totalLen - 1; i >= totalLen - 8; i--) {
    padded[i] = b & 0xff;
    b = (b / 256) | 0;
  }

  const W = new Uint32Array(160); // 80 words * 2

  for (let offset = 0; offset < totalLen; offset += 128) {
    // Load 16 64-bit words into W (big-endian per word)
    for (let t = 0; t < 16; t++) {
      const i = offset + (t << 3);
      W[t * 2]     = (padded[i]     << 24) | (padded[i + 1] << 16) | (padded[i + 2] << 8) | padded[i + 3];
      W[t * 2 + 1] = (padded[i + 4] << 24) | (padded[i + 5] << 16) | (padded[i + 6] << 8) | padded[i + 7];
    }

    // Extend W[16..79]
    for (let t = 16; t < 80; t++) {
      const idx = t * 2, idx15 = (t - 15) * 2, idx2 = (t - 2) * 2, idx16 = (t - 16) * 2, idx7 = (t - 7) * 2;

      // s0 = rotR64(W[t-15], 1) ^ rotR64(W[t-15], 8) ^ (W[t-15] >> 7)
      const w15_hi = W[idx15], w15_lo = W[idx15 + 1];
      const s0_r1_hi = ((w15_hi >>> 1) | (w15_lo << 31)) >>> 0;
      const s0_r1_lo = ((w15_lo >>> 1) | (w15_hi << 31)) >>> 0;
      const s0_r8_hi = ((w15_hi >>> 8) | (w15_lo << 24)) >>> 0;
      const s0_r8_lo = ((w15_lo >>> 8) | (w15_hi << 24)) >>> 0;
      const s0_s7_hi = w15_hi >>> 7;
      const s0_s7_lo = ((w15_lo >>> 7) | (w15_hi << 25)) >>> 0;
      const s0_hi = (s0_r1_hi ^ s0_r8_hi ^ s0_s7_hi) >>> 0;
      const s0_lo = (s0_r1_lo ^ s0_r8_lo ^ s0_s7_lo) >>> 0;

      // s1 = rotR64(W[t-2], 19) ^ rotR64(W[t-2], 61) ^ (W[t-2] >> 6)
      const w2_hi = W[idx2], w2_lo = W[idx2 + 1];
      const s1_r19_hi = ((w2_hi >>> 19) | (w2_lo << 13)) >>> 0;
      const s1_r19_lo = ((w2_lo >>> 19) | (w2_hi << 13)) >>> 0;
      // rotR by 61: n>32, m=29
      const s1_r61_hi = ((w2_lo >>> 29) | (w2_hi << 3)) >>> 0;
      const s1_r61_lo = ((w2_hi >>> 29) | (w2_lo << 3)) >>> 0;
      const s1_s6_hi = w2_hi >>> 6;
      const s1_s6_lo = ((w2_lo >>> 6) | (w2_hi << 26)) >>> 0;
      const s1_hi = (s1_r19_hi ^ s1_r61_hi ^ s1_s6_hi) >>> 0;
      const s1_lo = (s1_r19_lo ^ s1_r61_lo ^ s1_s6_lo) >>> 0;

      // W[t] = W[t-16] + s0 + W[t-7] + s1
      let sum_lo = (W[idx16 + 1] + s0_lo) >>> 0;
      let carry = (sum_lo < s0_lo) ? 1 : 0;
      let sum_hi = ((W[idx16] + s0_hi) >>> 0) + carry;

      sum_lo = (sum_lo + W[idx7 + 1]) >>> 0;
      carry = (sum_lo < W[idx7 + 1]) ? 1 : 0;
      sum_hi = ((sum_hi + W[idx7]) >>> 0) + carry;

      sum_lo = (sum_lo + s1_lo) >>> 0;
      carry = (sum_lo < s1_lo) ? 1 : 0;
      sum_hi = ((sum_hi + s1_hi) >>> 0) + carry;

      W[idx] = sum_hi >>> 0;
      W[idx + 1] = sum_lo;
    }

    // Working variables
    let a_hi = H0_hi, a_lo = H0_lo;
    let b_hi = H1_hi, b_lo = H1_lo;
    let c_hi = H2_hi, c_lo = H2_lo;
    let d_hi = H3_hi, d_lo = H3_lo;
    let e_hi = H4_hi, e_lo = H4_lo;
    let f_hi = H5_hi, f_lo = H5_lo;
    let g_hi = H6_hi, g_lo = H6_lo;
    let h_hi = H7_hi, h_lo = H7_lo;

    for (let t = 0; t < 80; t++) {
      const idx = t * 2;

      // S1 = rotR64(e, 14) ^ rotR64(e, 18) ^ rotR64(e, 41)
      const e14_hi = ((e_hi >>> 14) | (e_lo << 18)) >>> 0;
      const e14_lo = ((e_lo >>> 14) | (e_hi << 18)) >>> 0;
      const e18_hi = ((e_hi >>> 18) | (e_lo << 14)) >>> 0;
      const e18_lo = ((e_lo >>> 18) | (e_hi << 14)) >>> 0;
      // rotR by 41: n>32, m=9
      const e41_hi = ((e_lo >>> 9) | (e_hi << 23)) >>> 0;
      const e41_lo = ((e_hi >>> 9) | (e_lo << 23)) >>> 0;
      const S1_hi = (e14_hi ^ e18_hi ^ e41_hi) >>> 0;
      const S1_lo = (e14_lo ^ e18_lo ^ e41_lo) >>> 0;

      // ch = (e & f) ^ (~e & g)
      const ch_hi = (((e_hi & f_hi) ^ (~e_hi & g_hi)) >>> 0);
      const ch_lo = (((e_lo & f_lo) ^ (~e_lo & g_lo)) >>> 0);

      // temp1 = h + S1 + ch + K512[t] + W[t]
      let t1_lo = (h_lo + S1_lo) >>> 0;
      let carry = (t1_lo < S1_lo) ? 1 : 0;
      let t1_hi = ((h_hi + S1_hi) >>> 0) + carry;

      t1_lo = (t1_lo + ch_lo) >>> 0;
      carry = (t1_lo < ch_lo) ? 1 : 0;
      t1_hi = ((t1_hi + ch_hi) >>> 0) + carry;

      const k_hi = K512_hi[t], k_lo = K512_lo[t];
      t1_lo = (t1_lo + k_lo) >>> 0;
      carry = (t1_lo < k_lo) ? 1 : 0;
      t1_hi = ((t1_hi + k_hi) >>> 0) + carry;

      const w_hi = W[idx], w_lo = W[idx + 1];
      t1_lo = (t1_lo + w_lo) >>> 0;
      carry = (t1_lo < w_lo) ? 1 : 0;
      t1_hi = ((t1_hi + w_hi) >>> 0) + carry;
      t1_hi = t1_hi >>> 0;

      // S0 = rotR64(a, 28) ^ rotR64(a, 34) ^ rotR64(a, 39)
      const a28_hi = ((a_hi >>> 28) | (a_lo << 4)) >>> 0;
      const a28_lo = ((a_lo >>> 28) | (a_hi << 4)) >>> 0;
      // rotR by 34: n>32, m=2
      const a34_hi = ((a_lo >>> 2) | (a_hi << 30)) >>> 0;
      const a34_lo = ((a_hi >>> 2) | (a_lo << 30)) >>> 0;
      // rotR by 39: n>32, m=7
      const a39_hi = ((a_lo >>> 7) | (a_hi << 25)) >>> 0;
      const a39_lo = ((a_hi >>> 7) | (a_lo << 25)) >>> 0;
      const S0_hi = (a28_hi ^ a34_hi ^ a39_hi) >>> 0;
      const S0_lo = (a28_lo ^ a34_lo ^ a39_lo) >>> 0;

      // maj = (a & b) ^ (a & c) ^ (b & c)
      const maj_hi = (((a_hi & b_hi) ^ (a_hi & c_hi) ^ (b_hi & c_hi)) >>> 0);
      const maj_lo = (((a_lo & b_lo) ^ (a_lo & c_lo) ^ (b_lo & c_lo)) >>> 0);

      // temp2 = S0 + maj
      let t2_lo = (S0_lo + maj_lo) >>> 0;
      carry = (t2_lo < maj_lo) ? 1 : 0;
      let t2_hi = ((S0_hi + maj_hi) >>> 0) + carry;
      t2_hi = t2_hi >>> 0;

      // Update working variables
      h_hi = g_hi; h_lo = g_lo;
      g_hi = f_hi; g_lo = f_lo;
      f_hi = e_hi; f_lo = e_lo;
      let e_new_lo = (d_lo + t1_lo) >>> 0;
      carry = (e_new_lo < t1_lo) ? 1 : 0;
      let e_new_hi = ((d_hi + t1_hi) >>> 0) + carry;
      e_hi = e_new_hi >>> 0; e_lo = e_new_lo;
      d_hi = c_hi; d_lo = c_lo;
      c_hi = b_hi; c_lo = b_lo;
      b_hi = a_hi; b_lo = a_lo;
      let a_new_lo = (t1_lo + t2_lo) >>> 0;
      carry = (a_new_lo < t2_lo) ? 1 : 0;
      let a_new_hi = ((t1_hi + t2_hi) >>> 0) + carry;
      a_hi = a_new_hi >>> 0; a_lo = a_new_lo;
    }

    // Add to hash
    let carry = (H0_lo + a_lo) > 0xffffffff ? 1 : 0; H0_lo = (H0_lo + a_lo) >>> 0; H0_hi = ((H0_hi + a_hi) >>> 0) + carry; H0_hi = H0_hi >>> 0;
    H1_lo = (H1_lo + b_lo) >>> 0; carry = (H1_lo < b_lo) ? 1 : 0; H1_hi = ((H1_hi + b_hi) >>> 0) + carry; H1_hi = H1_hi >>> 0;
    H2_lo = (H2_lo + c_lo) >>> 0; carry = (H2_lo < c_lo) ? 1 : 0; H2_hi = ((H2_hi + c_hi) >>> 0) + carry; H2_hi = H2_hi >>> 0;
    H3_lo = (H3_lo + d_lo) >>> 0; carry = (H3_lo < d_lo) ? 1 : 0; H3_hi = ((H3_hi + d_hi) >>> 0) + carry; H3_hi = H3_hi >>> 0;
    H4_lo = (H4_lo + e_lo) >>> 0; carry = (H4_lo < e_lo) ? 1 : 0; H4_hi = ((H4_hi + e_hi) >>> 0) + carry; H4_hi = H4_hi >>> 0;
    H5_lo = (H5_lo + f_lo) >>> 0; carry = (H5_lo < f_lo) ? 1 : 0; H5_hi = ((H5_hi + f_hi) >>> 0) + carry; H5_hi = H5_hi >>> 0;
    H6_lo = (H6_lo + g_lo) >>> 0; carry = (H6_lo < g_lo) ? 1 : 0; H6_hi = ((H6_hi + g_hi) >>> 0) + carry; H6_hi = H6_hi >>> 0;
    H7_lo = (H7_lo + h_lo) >>> 0; carry = (H7_lo < h_lo) ? 1 : 0; H7_hi = ((H7_hi + h_hi) >>> 0) + carry; H7_hi = H7_hi >>> 0;
  }

  const out = new Uint8Array(64);
  out[0]  = (H0_hi >>> 24) & 0xff; out[1]  = (H0_hi >>> 16) & 0xff; out[2]  = (H0_hi >>> 8) & 0xff; out[3]  = H0_hi & 0xff;
  out[4]  = (H0_lo >>> 24) & 0xff; out[5]  = (H0_lo >>> 16) & 0xff; out[6]  = (H0_lo >>> 8) & 0xff; out[7]  = H0_lo & 0xff;
  out[8]  = (H1_hi >>> 24) & 0xff; out[9]  = (H1_hi >>> 16) & 0xff; out[10] = (H1_hi >>> 8) & 0xff; out[11] = H1_hi & 0xff;
  out[12] = (H1_lo >>> 24) & 0xff; out[13] = (H1_lo >>> 16) & 0xff; out[14] = (H1_lo >>> 8) & 0xff; out[15] = H1_lo & 0xff;
  out[16] = (H2_hi >>> 24) & 0xff; out[17] = (H2_hi >>> 16) & 0xff; out[18] = (H2_hi >>> 8) & 0xff; out[19] = H2_hi & 0xff;
  out[20] = (H2_lo >>> 24) & 0xff; out[21] = (H2_lo >>> 16) & 0xff; out[22] = (H2_lo >>> 8) & 0xff; out[23] = H2_lo & 0xff;
  out[24] = (H3_hi >>> 24) & 0xff; out[25] = (H3_hi >>> 16) & 0xff; out[26] = (H3_hi >>> 8) & 0xff; out[27] = H3_hi & 0xff;
  out[28] = (H3_lo >>> 24) & 0xff; out[29] = (H3_lo >>> 16) & 0xff; out[30] = (H3_lo >>> 8) & 0xff; out[31] = H3_lo & 0xff;
  out[32] = (H4_hi >>> 24) & 0xff; out[33] = (H4_hi >>> 16) & 0xff; out[34] = (H4_hi >>> 8) & 0xff; out[35] = H4_hi & 0xff;
  out[36] = (H4_lo >>> 24) & 0xff; out[37] = (H4_lo >>> 16) & 0xff; out[38] = (H4_lo >>> 8) & 0xff; out[39] = H4_lo & 0xff;
  out[40] = (H5_hi >>> 24) & 0xff; out[41] = (H5_hi >>> 16) & 0xff; out[42] = (H5_hi >>> 8) & 0xff; out[43] = H5_hi & 0xff;
  out[44] = (H5_lo >>> 24) & 0xff; out[45] = (H5_lo >>> 16) & 0xff; out[46] = (H5_lo >>> 8) & 0xff; out[47] = H5_lo & 0xff;
  out[48] = (H6_hi >>> 24) & 0xff; out[49] = (H6_hi >>> 16) & 0xff; out[50] = (H6_hi >>> 8) & 0xff; out[51] = H6_hi & 0xff;
  out[52] = (H6_lo >>> 24) & 0xff; out[53] = (H6_lo >>> 16) & 0xff; out[54] = (H6_lo >>> 8) & 0xff; out[55] = H6_lo & 0xff;
  out[56] = (H7_hi >>> 24) & 0xff; out[57] = (H7_hi >>> 16) & 0xff; out[58] = (H7_hi >>> 8) & 0xff; out[59] = H7_hi & 0xff;
  out[60] = (H7_lo >>> 24) & 0xff; out[61] = (H7_lo >>> 16) & 0xff; out[62] = (H7_lo >>> 8) & 0xff; out[63] = H7_lo & 0xff;
  return outBytes === 64 ? out : out.subarray(0, outBytes);
}

export function sha512(data: Uint8Array): Uint8Array {
  return sha512Digest32(data, SHA512_INITIAL, 64);
}

export function sha384(data: Uint8Array): Uint8Array {
  return sha512Digest32(data, SHA384_INITIAL, 48);
}
