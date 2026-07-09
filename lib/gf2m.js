/* eslint-disable no-bitwise,no-plusplus,no-constant-condition,camelcase,no-param-reassign,no-continue,no-underscore-dangle,no-cond-assign */

/*
 * gf2m.js - low-level binary finite field GF(2^m) arithmetic for DSTU 4145.
 *
 * This module is the computational core of the library. Field elements and
 * intermediate products are represented as binary polynomials packed into
 * Uint32Array words in little-endian word order: word 0 holds the least
 * significant 32 coefficients (t^0..t^31), word 1 holds t^32..t^63, and so on.
 * Bit i of the packed number is the coefficient of the monomial t^i.
 *
 * Addition in GF(2^m) is bitwise XOR (there are no carries), and multiplication
 * is carry-less polynomial multiplication reduced modulo the field's reduction
 * polynomial. The reduction polynomial is passed around as an array `p` where
 * p[0] is the extension degree m and p[1..] are the exponents of the remaining
 * middle terms (a trinomial has one, a pentanomial has three); the t^0 term is
 * implicit and terminated by a trailing zero entry.
 *
 * The functions here operate on raw typed arrays and know nothing about curves;
 * the Field class in field.js wraps them with element semantics.
 */

/**
 * Compute the bit length of a big number stored as a little-endian Uint32Array,
 * i.e. one plus the index of its most significant set bit.
 * @param {Uint32Array} _bytes - packed number, little-endian word order.
 * @returns {number} number of significant bits.
 */
function blength(_bytes) {
  let r = 1;

  let t;

  let x;

  let nz;
  // Skip leading all-zero words to find the most significant non-empty word.
  nz = _bytes.length - 1;
  while (_bytes[nz] === 0) {
    nz--;
  }

  // Binary search for the highest set bit within the top word: repeatedly test
  // the upper half and fold it down, accumulating its bit offset into r.
  x = _bytes[nz];
  if ((t = x >>> 16) !== 0) {
    x = t;
    r += 16;
  }
  if ((t = x >> 8) !== 0) {
    x = t;
    r += 8;
  }
  if ((t = x >> 4) !== 0) {
    x = t;
    r += 4;
  }
  if ((t = x >> 2) !== 0) {
    x = t;
    r += 2;
  }
  if ((x >> 1) !== 0) {
    r += 1;
  }
  // Add the 32 bits contributed by each lower word below the top word.
  return r + nz * 32;
}

/* _bytes should be Uint32Array */
/**
 * Shift a packed little-endian number right by an arbitrary number of bits.
 * @param {Uint32Array} _bytes - packed number, little-endian word order.
 * @param {number} right - number of bits to shift right.
 * @param {boolean} inplace - when true, mutate and return `_bytes`; otherwise
 *   allocate a fresh Uint32Array of the same length.
 * @returns {Uint32Array} the shifted number.
 */
function shiftRight(_bytes, right, inplace) {
  // Split the shift into whole-word (wright) and sub-word (right) components.
  const wright = Math.floor(right / 32);
  right %= 32;

  let idx;

  const blen = _bytes.length;

  const left = 32 - right;

  // Low bits of each word that are shifted out and must carry down into the
  // next-lower word (re-inserted at the top via `<< left`).
  let mask_f = (1 << (1 + right)) - 1;

  let _rbytes;

  let tmp;

  if (right === 31) mask_f = 0xffffffff;

  if (inplace === true) {
    _rbytes = _bytes;
  } else {
    _rbytes = new Uint32Array(blen);
  }

  _rbytes[0] = _bytes[0] >>> right;
  for (idx = 1; idx < blen; idx++) {
    tmp = _bytes[idx] & mask_f;

    _rbytes[idx] = _bytes[idx] >>> right;
    // Bits leaving the bottom of word idx enter the top of word idx-1.
    _rbytes[idx - 1] |= tmp << left;
  }

  if (wright === 0) return _rbytes;

  // Apply the whole-word part of the shift by moving each word down wright slots.
  for (idx = 0; idx < blen; idx++) {
    _rbytes[idx] = _rbytes[idx + wright] || 0;
  }

  return _rbytes;
}

/**
 * Carry-less multiply two 32-bit binary polynomials into a 64-bit product.
 * Uses a windowed (comb) method with a precomputed table of small multiples.
 * @param {Uint32Array} ret - output buffer receiving the two-word product.
 * @param {number} offset - word index in `ret` for the low half; high half at offset+1.
 * @param {number} a - first 32-bit polynomial operand.
 * @param {number} b - second 32-bit polynomial operand.
 * @returns {void}
 */
function mul_1x1(ret, offset, a, b) {
  // The table only covers the low 30 bits of `a`; the top 2 bits are handled
  // separately below to avoid overflowing the 32-bit table entries.
  const top2b = a >>> 30;
  const ol = offset;
  const oh = offset + 1;

  let s;
  let l;
  let h;

  // Precompute a * {0,1,2,3,4,5,6,7} in GF(2) so 3-bit windows of b can be
  // combined by table lookup (multiples are XOR-combinations of a1, a2, a4).
  const a1 = a & 0x3fffffff;
  const a2 = a1 << 1;
  const a4 = a2 << 1;

  const tab = [0, a1, a2, a1 ^ a2, a4, a1 ^ a4, a2 ^ a4, a1 ^ a2 ^ a4];

  // Scan b in 3-bit windows: each contributes s shifted by its bit position,
  // with l/h accumulating the low/high 32 bits of the 64-bit product.
  s = tab[b & 0x7];
  l = s;
  s = tab[(b >>> 3) & 0x7];
  l ^= s << 3;
  h = s >>> 29;
  s = tab[(b >>> 6) & 0x7];
  l ^= s << 6;
  h ^= s >>> 26;
  s = tab[(b >>> 9) & 0x7];
  l ^= s << 9;
  h ^= s >>> 23;
  s = tab[(b >>> 12) & 0x7];
  l ^= s << 12;
  h ^= s >>> 20;
  s = tab[(b >>> 15) & 0x7];
  l ^= s << 15;
  h ^= s >>> 17;
  s = tab[(b >>> 18) & 0x7];
  l ^= s << 18;
  h ^= s >>> 14;
  s = tab[(b >>> 21) & 0x7];
  l ^= s << 21;
  h ^= s >>> 11;
  s = tab[(b >>> 24) & 0x7];
  l ^= s << 24;
  h ^= s >>> 8;
  s = tab[(b >>> 27) & 0x7];
  l ^= s << 27;
  h ^= s >>> 5;
  s = tab[b >>> 30];
  l ^= s << 30;
  h ^= s >>> 2;

  // Add back the contribution of a's two high bits (t^30, t^31) that were
  // masked out of the table: each is a copy of b shifted to its position.
  if (top2b & 1) {
    l ^= b << 30;
    h ^= b >>> 2;
  }
  if (top2b & 2) {
    l ^= b << 31;
    h ^= b >>> 1;
  }

  ret[oh] = h;
  ret[ol] = l;
}

/**
 * Carry-less multiply two 2-word (64-bit) binary polynomials into a 128-bit
 * product using one level of Karatsuba (three 32x32 multiplies instead of four).
 * @param {number} a1 - high word of the first operand.
 * @param {number} a0 - low word of the first operand.
 * @param {number} b1 - high word of the second operand.
 * @param {number} b0 - low word of the second operand.
 * @param {Uint32Array} ret - scratch/output buffer of length 6; result lands in ret[0..3].
 * @returns {Uint32Array} `ret`, with the four-word product in words 0..3.
 */
function mul_2x2(a1, a0, b1, b0, ret) {
  // Karatsuba: high = a1*b1 (words 2,3), low = a0*b0 (words 0,1),
  // and the cross/middle term (a0^a1)*(b0^b1) (words 4,5).
  mul_1x1(ret, 2, a1, b1);
  mul_1x1(ret, 0, a0, b0);
  mul_1x1(ret, 4, a0 ^ a1, b0 ^ b1);

  // Fold the middle term (with high and low subtracted off, i.e. XORed) into
  // the two central words of the 128-bit result.
  ret[2] ^= ret[5] ^ ret[1] ^ ret[3];
  ret[1] = ret[3] ^ ret[2] ^ ret[0] ^ ret[4] ^ ret[5];
  ret[4] = 0;
  ret[5] = 0;

  return ret;
}

/**
 * Carry-less multiply two arbitrary-length binary polynomials (unreduced).
 * Schoolbook over 64-bit blocks, accumulating partial products with XOR.
 * @param {Uint32Array} a - first polynomial, little-endian word order.
 * @param {Uint32Array} b - second polynomial, little-endian word order.
 * @param {Uint32Array} s - output buffer for the full (double-width) product; zeroed first.
 * @returns {void}
 */
function fmul(a, b, s) {
  let y1;
  let y0;
  let x1;
  let x0;
  const a_len = a.length;
  const b_len = b.length;

  for (let i = 0; i < s.length; i++) {
    s[i] = 0;
  }

  const x22 = new Uint32Array(6);

  // Multiply block-by-block (2 words each) and XOR every 128-bit partial
  // product into place at word offset i+j (odd-length tails padded with 0).
  for (let j = 0; j < b_len; j += 2) {
    y0 = b[j];
    y1 = j + 1 === b_len ? 0 : b[j + 1];

    for (let i = 0; i < a_len; i += 2) {
      x0 = a[i];
      x1 = i + 1 === a_len ? 0 : a[i + 1];

      mul_2x2(x1, x0, y1, y0, x22);
      s[j + i + 0] ^= x22[0];
      s[j + i + 1] ^= x22[1];
      s[j + i + 2] ^= x22[2];
      s[j + i + 3] ^= x22[3];
    }
  }
}

const BITS = 32; // machine word size in bits (words are Uint32)

/**
 * Reduce a binary polynomial modulo the field's reduction polynomial.
 * @param {Uint32Array} a - polynomial to reduce (typically a double-width product).
 * @param {number[]} p - reduction polynomial descriptor: p[0] is the degree m and
 *   p[1..] are the exponents of the middle terms, terminated by a trailing 0;
 *   the t^0 term is implicit.
 * @param {Uint32Array} [ret] - optional output buffer; when omitted a new array
 *   the size of `a` is allocated.
 * @returns {Uint32Array} the reduced polynomial (degree < m).
 */
function fmod(a, p, ret) {
  let ret_len;
  let zz;
  let k;
  let n;
  let d0;
  let d1;
  let tmp_ulong;
  let j;

  if (ret) {
    ret_len = ret.length;
    for (k = 0; k < ret_len; k++) ret[k] = a[k];
  } else {
    ret_len = a.length;
    ret = new Uint32Array(ret_len);
    for (k = 0; k < ret_len; k++) ret[k] = a[k];
  }

  /* start reduction */
  // Reduction relies on the identity t^m = t^p[1] + ... + 1 (mod f). Any word
  // above word dN (the word containing bit m) is folded down by re-expressing
  // its bits through that identity. dN is the index of the highest live word.
  const dN = Math.floor(p[0] / BITS);
  for (j = ret_len - 1; j > dN;) {
    // Take the whole high word zz, clear it, then XOR its reduced images back
    // in at the lower positions dictated by each term of the polynomial.
    zz = ret[j];
    if (ret[j] === 0) {
      j--;
      continue;
    }
    ret[j] = 0;

    for (k = 1; p[k]; k++) {
      /* reducing component t^p[k] */
      // Each high bit at exponent E maps to E-(m-p[k]); n/d0 split that offset
      // into word and in-word bit shifts, spilling across two words when d0!=0.
      n = p[0] - p[k];
      d0 = n % BITS;
      d1 = BITS - d0;
      n = Math.floor(n / BITS);
      ret[j - n] ^= zz >>> d0;
      if (d0) ret[j - n - 1] ^= zz << d1;
    }

    /* reducing component t^0 */
    n = dN;
    d0 = p[0] % BITS;
    d1 = BITS - d0;
    ret[j - n] ^= zz >>> d0;
    if (d0) ret[j - n - 1] ^= zz << d1;
  }

  /* final round of reduction */
  // The top word dN may still carry bits at or above exponent m; fold just those
  // overflow bits (zz) down until nothing remains above bit m.
  while (j === dN) {
    d0 = p[0] % BITS;
    zz = ret[dN] >>> d0;
    if (zz === 0) break;
    d1 = BITS - d0;

    /* clear up the top d1 bits */
    if (d0) ret[dN] = (ret[dN] << d1) >>> d1;
    else ret[dN] = 0;
    ret[0] ^= zz; /* reduction t^0 component */

    for (k = 1; p[k]; k++) {
      /* reducing component t^p[k] */
      n = Math.floor(p[k] / BITS);
      d0 = p[k] % BITS;
      d1 = BITS - d0;
      ret[n] ^= zz << d0;
      tmp_ulong = zz >>> d1;
      if (d0 && tmp_ulong) ret[n + 1] ^= tmp_ulong;
    }
  }

  return ret;
}

/**
 * Compute the multiplicative inverse of a field element via the binary
 * (almost-inverse) extended Euclidean algorithm for GF(2^m).
 * @param {Uint32Array} a - element to invert (already reduced, degree < m).
 * @param {Uint32Array} p - the reduction polynomial as a packed bit array (f(t)).
 * @param {Uint32Array} ret - output buffer receiving a^{-1}.
 * @returns {void}
 */
function finv_fast(a, p, ret) {
  // Maintain the invariant b*a === u and c*a === v (mod f); the algorithm drives
  // u toward 1 with parallel operations on b, at which point b is the inverse.
  let b = new Uint32Array(a.length);
  let c = new Uint32Array(a.length);
  let v = new Uint32Array(a.length);

  b[0] = 1;
  let u = a;
  for (let idx = 0; idx < p.length; idx++) {
    v[idx] = p[idx];
  }

  let ubits = blength(u);
  let vbits = blength(v);

  let iter = 1000; // hard cap to guarantee termination on malformed input
  while (1) {
    iter--;
    if (iter <= 0) throw new Error("Internal error, loop");
    if (ubits < 0) throw new Error("Internal error");
    // While u is even, divide u by t (shift right one bit). To keep b*a === u,
    // b must also be divisible by t: if b is odd, add f first (adding a multiple
    // of f does not change the residue) so b becomes even before shifting.
    while (ubits && !(u[0] & 1)) {
      let u0 = u[0];
      let b0 = b[0];
      let u1;
      let b1;

      // mask is all-ones when b is odd, selecting whether to fold in p (=f).
      const mask = b0 & 1 ? 0xffffffff : 0;
      b0 ^= p[0] & mask;

      let idx;
      for (idx = 0; idx < p.length - 1; idx++) {
        u1 = u[idx + 1];
        u[idx] = (u0 >>> 1) | (u1 << 31);
        u0 = u1;
        b1 = b[idx + 1] ^ (p[idx + 1] & mask);
        b[idx] = (b0 >>> 1) | (b1 << 31);
        b0 = b1;
      }

      u[idx] = u0 >> 1;
      b[idx] = b0 >> 1;
      ubits--;
    }

    // u has been reduced to 1: b now holds a^{-1}.
    if (ubits <= 32 && u[0] === 1) break;

    // Ensure u is the larger operand so the subtraction below makes progress;
    // swap the (u,b) pair with (v,c) when necessary.
    if (ubits < vbits) {
      let tmp = ubits;
      ubits = vbits;
      vbits = tmp;
      tmp = u;
      u = v;
      v = tmp;
      tmp = b;
      b = c;
      c = tmp;
    }

    // u := u + v (XOR) cancels the top bits of u; mirror on b to keep b*a === u.
    for (let idx = 0; idx < p.length; idx++) {
      u[idx] ^= v[idx];
      b[idx] ^= c[idx];
    }

    // The XOR may have cleared several high bits, so recompute u's bit length.
    if (ubits === vbits) {
      ubits = blength(u);
    }
  }

  for (let idx = 0; idx < b.length; idx++) {
    ret[idx] = b[idx];
  }
}

/**
 * Compute the multiplicative inverse via Fermat's little theorem, using the
 * identity a^{-1} = a^(2^m - 2) in GF(2^m).
 * @param {number} m - the field extension degree.
 * @param {Uint32Array} a - element to invert (already reduced).
 * @param {number[]} p - reduction polynomial descriptor (see fmod).
 * @param {Uint32Array} ret - output buffer receiving a^{-1}.
 * @returns {void}
 */
function finv_fermat(m, a, p, ret) {
  const len = a.length * 2;

  let x = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    x[i] = a[i];
  }

  let temp = new Uint32Array(len);

  // Exponent 2^m - 2 is (m-1) one-bits followed by a trailing zero. Starting
  // from x = a (the leading one-bit), each iteration squares then multiplies by
  // a to consume one more one-bit; the final square consumes the trailing zero.
  for (let i = 0; i < m - 2; i++) {
    fmul(x, x, temp);
    fmod(temp, p, x);

    fmul(x, a, temp);
    fmod(temp, p, x);
  }

  fmul(x, x, temp);
  fmod(temp, p, x);

  for (let i = 0; i < len; i++) {
    ret[i] = x[i];
  }
}

export {
  mul_2x2,
  shiftRight,
  blength,
  fmod as mod,
  fmul as mul,
  finv_fast as inv_fast,
  finv_fermat as inv_slow
};
