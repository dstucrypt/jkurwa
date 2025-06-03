import { Buffer } from "buffer";
import * as _pure from "./gf2m.js";

let impl = _pure;

class Field {
  constructor(in_value, fmt, curve) {
    if (curve === undefined || curve.mod_words === undefined) {
      throw new Error("pass curve to field constructor");
    }

    if (in_value !== null && in_value._is_field) throw new Error("wtf");

    if (in_value === null) {
      this.bytes = new Uint32Array(curve.mod_words);
      this.length = curve.mod_words;
    } else {
      this.setValue(in_value, fmt, curve.mod_words);
    }

    this._is_field = true;
    this.curve = curve;
    this.mod_bits = curve.mod_bits;
    this.mod_words = curve.mod_words;
  }

  toString(raw) {
    let txt = "",
      chr,
      skip = true,
      _bytes = this.bytes;

    for (let i = _bytes.length - 1; i >= 0; i--) {
      chr = _bytes[i].toString(16);
      if (skip && _bytes[i] == 0) {
        continue;
      }
      while (chr.length < 8 && skip === false) chr = "0" + chr;
      txt += chr;
      skip = false;
    }

    if (raw === true) {
      return txt;
    }

    return "<Field " + txt + ">";
  }

  mod_mul(that) {
    let s = this.curve.mod_tmp;
    impl.mul(this.bytes, that.bytes, s);
    s = impl.mod(s, this.mod_bits).subarray(0, this.mod_words);
    return new Field(s, undefined, this.curve);
  }

  mod_sqr() {
    return this.mod_mul(this);
  }

  mod() {
    let rbuf = impl.mod(this.bytes, this.mod_bits);
    return new Field(rbuf, undefined, this.curve);
  }

  addM(that, _from) {
    let that_b = that.bytes,
      that_len = that_b.length,
      this_b = _from || this.bytes,
      to_b = this.bytes,
      iter_len = Math.max((to_b || _from).length, that_len),
      i;

    if (to_b.length < that_len) {
      to_b = new Uint32Array(this.mod_words);
    }

    for (i = 0; i < iter_len; i++) {
      to_b[i] = this_b[i] ^ (that_b[i] || 0);
    }

    this.bytes = to_b;
    this.length = to_b.length;
  }

  add(that) {
    let ret = new Field(null, undefined, this.curve);
    ret.addM(that, this.bytes);
    return ret;
  }

  is_zero() {
    let blen = this.length,
      idx;
    for (idx = 0; idx < blen; idx++) {
      if (this.bytes[idx] !== 0) return false;
    }

    return true;
  }

  equals(other) {
    let blen = this.length,
      olen = other.length,
      idx,
      bb = this.bytes,
      diff = 0,
      ob = other.bytes;

    while (ob[olen - 1] === 0) olen--;

    while (bb[blen - 1] === 0) blen--;

    if (olen != blen) {
      return false;
    }

    for (idx = 0; idx < blen; idx++) {
      diff |= this.bytes[idx] ^ ob[idx];
    }

    return diff === 0;
  }

  less(other) {
    let blen = this.length,
      olen = other.length,
      idx,
      bb = this.bytes,
      diff = 0,
      ob = other.bytes;

    while (ob[olen - 1] === 0) olen--;

    while (bb[blen - 1] === 0) blen--;

    if (olen > blen) {
      return true;
    }

    return bb[blen] < ob[olen];
  }

  bitLength() {
    return _pure.blength(this.bytes);
  }

  testBit(n) {
    let test_word = Math.floor(n / 32),
      test_bit = n % 32,
      word = this.bytes[test_word],
      mask = 1 << test_bit;

    if (word === undefined) return true;

    return (word & mask) !== 0;
  }

  clone() {
    return new Field(new Uint32Array(this.bytes), undefined, this.curve);
  }

  clearBit(n) {
    let test_word = Math.floor(n / 32),
      test_bit = n % 32,
      word = this.bytes[test_word],
      mask = 1 << test_bit;

    if (word === undefined) return this;

    word ^= word & mask;

    let ret = this.clone();
    ret.bytes[test_word] = word;
    return ret;
  }

  setBit(n) {
    let test_word = Math.floor(n / 32),
      test_bit = n % 32,
      word = this.bytes[test_word],
      mask = 1 << test_bit;

    if (word === undefined) return this;

    let ret = this.clone();
    ret.bytes[test_word] |= mask;
    return ret;
  }

  shiftRight(bits) {
    if (bits === 0) return this.clone();

    return new Field(
      _pure.shiftRight(this.bytes, bits, false),
      undefined,
      this.curve
    );
  }

  shiftRightM(bits) {
    if (bits === 0) return;
    _pure.shiftRight(this.bytes, bits, true);
  }

  buf8() {
    let ret = new Uint8Array(this.bytes.length * 4);
    let l = ret.length;
    let idx;

    for (idx = 0; idx < this.bytes.length; idx++) {
      ret[l - idx * 4 - 1] = this.bytes[idx] & 0xff;
      ret[l - idx * 4 - 2] = (this.bytes[idx] >>> 8) & 0xff;
      ret[l - idx * 4 - 3] = (this.bytes[idx] >>> 16) & 0xff;
      ret[l - idx * 4 - 4] = (this.bytes[idx] >>> 24) & 0xff;
    }

    return ret;
  }

  le() {
    let bytes = Math.ceil(this.curve.m / 8);
    let data = this.buf8();
    data = Array.prototype.slice.call(data, 0);
    return Buffer.from(data.reverse()).slice(0, bytes);
  }

  truncate_buf8() {
    let ret = this.buf8(),
      start = ret.length - this.curve.order.bitLength() / 8;

    if (start < 0) {
      return ret;
    }

    return ret.subarray(start);
  }

  is_negative() {
    return false;
  }

  trace() {
    let bitm_l = this.curve.m;
    let idx;
    let rv = this;

    for (idx = 1; idx <= bitm_l - 1; idx++) {
      rv = rv.mod_mul(rv);
      rv.addM(this);
    }

    return rv.bytes[0] & 1;
  }

  setValue(in_value, fmt, mod_words) {
    let vidx, bpos, size, value, idx, chr, code;

    if (in_value !== null && in_value._is_field) throw new Error("wtf");

    if (fmt === undefined || fmt === "buf32") {
      this.bytes = in_value;
      this.length = in_value.length;
      return;
    }

    if (fmt === "hex") {
      this.bytes = from_hex(in_value, mod_words);
      this.length = this.bytes.length;
      return;
    }

    if (fmt === "bn") {
      in_value = in_value.toArray();
      fmt = "buf8";
    }

    if (fmt === "buf8") {
      this.bytes = from_u8(in_value, mod_words);
      this.length = this.bytes.length;
    }
  }

  invert(inplace, _reuse_buf) {
    let a = impl.mod(this.bytes, this.mod_bits);
    let p = this.curve.calc_modulus(this.mod_bits);
    impl.inv(a, p, a);

    return new Field(a, undefined, this.curve);
  }

  static detect_format(in_value) {
    if (typeof in_value === "string") {
      return "hex";
    } else if (in_value instanceof Uint8Array) {
      return "buf8";
    } else if (in_value instanceof Uint32Array) {
      return "buf32";
    } else {
      throw new Error("Unknown format");
    }
  }

  static parse_sign(in_value, fmt, curve) {
    let field = new Field(in_value, fmt, curve);
    return field;
  }
}

const HEX = "0123456789ABCDEF";
function from_hex(in_value, max_size) {
  let idx;
  let chr;
  let code;
  let vidx = 0;
  let bpos = 0;
  let size = Math.ceil(in_value.length / 8);
  size = Math.max(size, max_size || size);
  let value = new Uint32Array(size);
  for (idx = in_value.length - 1; idx >= 0; idx--) {
    chr = in_value.charAt(idx).toUpperCase();
    code = HEX.indexOf(chr);
    bpos = bpos % 8;
    if (code < 0) {
      throw new Error("Wrong input at " + idx);
    }
    value[vidx] |= code << (bpos * 4);
    if (bpos == 7) vidx++;
    bpos++;
  }
  return value;
}

function from_u8(in_value, max_size) {
  let vidx = 0;
  let bpos = 0;
  let size = Math.ceil(in_value.length / 4);
  size = Math.max(size, max_size || size);
  let value = new Uint32Array(size);
  let idx;
  let code;

  if (in_value.toString() === "[object Uint32Array]") {
    throw new Error("fuck off");
  }

  for (idx = in_value.length - 1; idx >= 0; idx--) {
    code = in_value[idx];
    bpos = bpos % 4;

    if (code < 0) {
      code = 256 + code;
    }
    value[vidx] |= code << (bpos * 8);

    if (bpos === 3) vidx++;
    bpos++;
  }

  return value;
}

function set_impl(_impl) {
  impl = _impl;
}

export default Field;
export { Field, from_hex, from_u8, set_impl };
