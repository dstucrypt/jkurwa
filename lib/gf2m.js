/* eslint-disable no-bitwise,no-plusplus,no-constant-condition,camelcase,no-param-reassign,no-continue,no-underscore-dangle,no-cond-assign */

function blength(_bytes) {
  let r = 1;

  let t;

  let x;

  let nz;
  nz = _bytes.length - 1;
  while (_bytes[nz] === 0) {
    nz--;
  }

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
  if ((t = x >> 1) !== 0) {
    x = t;
    r += 1;
  }
  return r + nz * 32;
}

/* _bytes should be Uint32Array */
function shiftRight(_bytes, right, inplace) {
  const wright = Math.floor(right / 32);
  right %= 32;

  let idx;

  const blen = _bytes.length;

  const left = 32 - right;

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
    _rbytes[idx - 1] |= tmp << left;
  }

  if (wright === 0) return _rbytes;

  for (idx = 0; idx < blen; idx++) {
    _rbytes[idx] = _rbytes[idx + wright] || 0;
  }

  return _rbytes;
}

function mul_1x1(ret, offset, a, b) {
  const top2b = a >>> 30;
  const ol = offset;
  const oh = offset + 1;

  let s;
  let l;
  let h;

  const a1 = a & 0x3fffffff;
  const a2 = a1 << 1;
  const a4 = a2 << 1;

  const tab = [0, a1, a2, a1 ^ a2, a4, a1 ^ a4, a2 ^ a4, a1 ^ a2 ^ a4];

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

function mul_2x2(a1, a0, b1, b0, ret) {
  mul_1x1(ret, 2, a1, b1);
  mul_1x1(ret, 0, a0, b0);
  mul_1x1(ret, 4, a0 ^ a1, b0 ^ b1);

  ret[2] ^= ret[5] ^ ret[1] ^ ret[3];
  ret[1] = ret[3] ^ ret[2] ^ ret[0] ^ ret[4] ^ ret[5];
  ret[4] = 0;
  ret[5] = 0;

  return ret;
}

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

const BITS = 32;

function fmod(a, p, ret) {
  let ret_len;
  let zz;
  let k;
  let n;
  let d0;
  let d1;
  let tmp_ulong;
  let j;

  if (!ret) {
    ret_len = a.length;
    ret = new Uint32Array(ret_len);
    for (k = 0; k < ret_len; k++) ret[k] = a[k];
  }

  /* start reduction */
  const dN = Math.floor(p[0] / BITS);
  for (j = ret_len - 1; j > dN; ) {
    zz = ret[j];
    if (ret[j] === 0) {
      j--;
      continue;
    }
    ret[j] = 0;

    for (k = 1; p[k]; k++) {
      /* reducing component t^p[k] */
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

function finv(a, p, ret) {
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

  while (1) {
    if (ubits < 0) throw new Error("Internal error");
    while (ubits && !(u[0] & 1)) {
      let u0 = u[0];
      let b0 = b[0];
      let u1;
      let b1;

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

    if (ubits <= 32 && u[0] === 1) break;

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

    for (let idx = 0; idx < p.length; idx++) {
      u[idx] ^= v[idx];
      b[idx] ^= c[idx];
    }

    if (ubits === vbits) {
      ubits = blength(u);
    }
  }

  for (let idx = 0; idx < b.length; idx++) {
    ret[idx] = b[idx];
  }
}

module.exports = {
  mul_2x2,
  shiftRight,
  blength,
  mod: fmod,
  mul: fmul,
  inv: finv
};
