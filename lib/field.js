import { Buffer } from "buffer";
import * as _pure from "./gf2m.js";

/*
 * field.js - element wrapper for the binary field GF(2^m) used by DSTU 4145.
 *
 * The Field class represents a single element of GF(2^m) (a curve coordinate,
 * scalar remainder, etc.) and gives it object semantics on top of the raw
 * Uint32Array polynomial arithmetic in gf2m.js: addition, multiplication with
 * reduction, squaring, inversion, trace, bit access, and conversions to/from
 * hex and byte buffers. Elements are immutable-by-convention (most operations
 * return a new Field), though a few *M methods mutate in place for speed.
 *
 * Elements carry a reference to their `curve`, which supplies the field
 * parameters: mod_bits (the reduction-polynomial descriptor), mod_words (the
 * number of 32-bit words per element), m (the extension degree), and scratch
 * buffers. The `impl` indirection lets the pure-JS backend be swapped out.
 */

// Active arithmetic backend; defaults to the pure-JS implementation but may be
// replaced via set_impl() (e.g. with a native/optimized variant).
let impl = _pure;

/**
 * A single element of the binary finite field GF(2^m).
 */
class Field {
  /**
   * @param {Uint32Array|Uint8Array|string|Object|null} in_value - the element
   *   value in the format given by `fmt`, or null for zero.
   * @param {string} [fmt] - input format: "buf32" (or undefined), "hex",
   *   "buf8", or "bn" (a big-number object exposing toArray()).
   * @param {Object} curve - the curve/field parameters (must define mod_words,
   *   mod_bits, m); required.
   */
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

  /**
   * Render the element as a big-endian hexadecimal string.
   * @param {boolean} [raw] - when true, return the bare hex; otherwise wrap it
   *   in "<Field ...>".
   * @returns {string} the hex representation.
   */
  toString(raw) {
    let txt = "",
      chr,
      skip = true,
      _bytes = this.bytes;

    // Iterate words from most to least significant; skip leading zero words so
    // the output has no leading zeros, then zero-pad the remaining words to 8 hex.
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

  /**
   * Multiply by another field element and reduce modulo the field polynomial.
   * @param {Field} that - the other operand.
   * @returns {Field} the reduced product (this * that mod f).
   */
  mod_mul(that) {
    // Multiply into the curve's shared scratch buffer, reduce, then trim to the
    // element's word width before wrapping the result.
    let s = this.curve.mod_tmp;
    impl.mul(this.bytes, that.bytes, s);
    s = impl.mod(s, this.mod_bits).subarray(0, this.mod_words);
    return new Field(s, undefined, this.curve);
  }

  /**
   * Square the element (multiply by itself) with reduction.
   * @returns {Field} this^2 mod f.
   */
  mod_sqr() {
    return this.mod_mul(this);
  }

  /**
   * Reduce the element modulo the field polynomial.
   * @returns {Field} the reduced element.
   */
  mod() {
    let rbuf = impl.mod(this.bytes, this.mod_bits);
    return new Field(rbuf, undefined, this.curve);
  }

  /**
   * In-place addition (XOR) of another element into this one.
   * @param {Field} that - the element to add.
   * @param {Uint32Array} [_from] - optional source words to add `that` to
   *   instead of this element's own words (result still stored on this).
   * @returns {void}
   */
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

    // Field addition is coefficient-wise XOR; missing high words of `that` are 0.
    for (i = 0; i < iter_len; i++) {
      to_b[i] = this_b[i] ^ (that_b[i] || 0);
    }

    this.bytes = to_b;
    this.length = to_b.length;
  }

  /**
   * Add (XOR) another element, returning a new element.
   * @param {Field} that - the element to add.
   * @returns {Field} the sum this + that.
   */
  add(that) {
    let ret = new Field(null, undefined, this.curve);
    ret.addM(that, this.bytes);
    return ret;
  }

  /**
   * Test whether the element is zero.
   * @returns {boolean} true if all coefficient words are zero.
   */
  is_zero() {
    let blen = this.length,
      idx;
    for (idx = 0; idx < blen; idx++) {
      if (this.bytes[idx] !== 0) return false;
    }

    return true;
  }

  /**
   * Test structural equality with another element.
   * @param {Field} other - the element to compare against.
   * @returns {boolean} true if both represent the same field value.
   */
  equals(other) {
    let blen = this.length,
      olen = other.length,
      idx,
      bb = this.bytes,
      diff = 0,
      ob = other.bytes;

    // Ignore leading zero words so operands of different buffer widths compare.
    while (ob[olen - 1] === 0) olen--;

    while (bb[blen - 1] === 0) blen--;

    if (olen != blen) {
      return false;
    }

    // Accumulate differences with OR so the loop runs to completion (constant-ish
    // time) rather than short-circuiting on the first mismatch.
    for (idx = 0; idx < blen; idx++) {
      diff |= this.bytes[idx] ^ ob[idx];
    }

    return diff === 0;
  }

  /**
   * Test whether this element compares as less than another.
   * @param {Field} other - the element to compare against.
   * @returns {boolean} true if this is considered smaller than `other`.
   */
  less(other) {
    let blen = this.length,
      olen = other.length,
      bb = this.bytes,
      ob = other.bytes;

    // Compare by significant-word count first, then by the top word.
    while (ob[olen - 1] === 0) olen--;

    while (bb[blen - 1] === 0) blen--;

    if (olen > blen) {
      return true;
    }

    return bb[blen] < ob[olen];
  }

  /**
   * Number of significant bits in the element.
   * @returns {number} the bit length.
   */
  bitLength() {
    return _pure.blength(this.bytes);
  }

  /**
   * Test whether bit n (the coefficient of t^n) is set.
   * @param {number} n - the bit index.
   * @returns {boolean} true if the bit is set; true also when n is past the
   *   allocated width (word undefined).
   */
  testBit(n) {
    let test_word = Math.floor(n / 32),
      test_bit = n % 32,
      word = this.bytes[test_word],
      mask = 1 << test_bit;

    if (word === undefined) return true;

    return (word & mask) !== 0;
  }

  /**
   * Create an independent copy of the element (with its own backing buffer).
   * @returns {Field} the cloned element.
   */
  clone() {
    return new Field(new Uint32Array(this.bytes), undefined, this.curve);
  }

  /**
   * Return a copy with bit n cleared.
   * @param {number} n - the bit index to clear.
   * @returns {Field} a new element with the bit cleared (or this if out of range).
   */
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

  /**
   * Return a copy with bit n set.
   * @param {number} n - the bit index to set.
   * @returns {Field} a new element with the bit set (or this if out of range).
   */
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

  /**
   * Shift the element right by a number of bits, returning a new element.
   * @param {number} bits - number of bits to shift.
   * @returns {Field} the shifted element.
   */
  shiftRight(bits) {
    if (bits === 0) return this.clone();

    return new Field(
      _pure.shiftRight(this.bytes, bits, false),
      undefined,
      this.curve
    );
  }

  /**
   * Shift the element right by a number of bits in place.
   * @param {number} bits - number of bits to shift.
   * @returns {void}
   */
  shiftRightM(bits) {
    if (bits === 0) return;
    _pure.shiftRight(this.bytes, bits, true);
  }

  /**
   * Serialize the element to a big-endian byte array.
   * @returns {Uint8Array} the element bytes, most significant byte first.
   */
  buf8() {
    let ret = new Uint8Array(this.bytes.length * 4);
    let l = ret.length;
    let idx;

    // Word 0 (least significant) is written at the end of the buffer, unpacking
    // each 32-bit word into 4 bytes in big-endian order.
    for (idx = 0; idx < this.bytes.length; idx++) {
      ret[l - idx * 4 - 1] = this.bytes[idx] & 0xff;
      ret[l - idx * 4 - 2] = (this.bytes[idx] >>> 8) & 0xff;
      ret[l - idx * 4 - 3] = (this.bytes[idx] >>> 16) & 0xff;
      ret[l - idx * 4 - 4] = (this.bytes[idx] >>> 24) & 0xff;
    }

    return ret;
  }

  /**
   * Serialize the element to a little-endian buffer truncated to the field size.
   * @returns {Buffer} the element bytes, least significant byte first,
   *   truncated to ceil(m/8) bytes.
   */
  le() {
    let bytes = Math.ceil(this.curve.m / 8);
    let data = this.buf8();
    data = Array.prototype.slice.call(data, 0);
    return Buffer.from(data.reverse()).slice(0, bytes);
  }

  /**
   * Serialize to big-endian bytes truncated to the curve order's byte length.
   * @returns {Uint8Array} the byte representation, cut to the order's width.
   */
  truncate_buf8() {
    let ret = this.buf8(),
      start = ret.length - this.curve.order.bitLength() / 8;

    if (start < 0) {
      return ret;
    }

    return ret.subarray(start);
  }

  /**
   * Sign predicate; binary-field elements are never negative.
   * @returns {boolean} always false.
   */
  is_negative() {
    return false;
  }

  /**
   * Compute the field trace Tr(x) = x + x^2 + x^4 + ... + x^(2^(m-1)).
   * @returns {number} the trace, 0 or 1 (an element of GF(2)).
   */
  trace() {
    let bitm_l = this.curve.m;
    let idx;
    let rv = this;

    // Horner-style accumulation: each step squares the running sum and adds x,
    // building x + x^2 + x^4 + ... + x^(2^(m-1)) over m-1 iterations.
    for (idx = 1; idx <= bitm_l - 1; idx++) {
      rv = rv.mod_mul(rv);
      rv.addM(this);
    }

    // The trace lies in GF(2), so only the lowest bit is meaningful.
    return rv.bytes[0] & 1;
  }

  /**
   * Populate this element's backing words from an input value and format.
   * @param {Uint32Array|Uint8Array|string|Object} in_value - the source value.
   * @param {string} [fmt] - "buf32"/undefined, "hex", "buf8", or "bn".
   * @param {number} mod_words - target word width for the field.
   * @returns {void}
   */
  setValue(in_value, fmt, mod_words) {

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

    // A big-number object is normalized to a big-endian byte array first.
    if (fmt === "bn") {
      in_value = in_value.toArray();
      fmt = "buf8";
    }

    if (fmt === "buf8") {
      this.bytes = from_u8(in_value, mod_words);
      this.length = this.bytes.length;
    }
  }

  /**
   * Compute the multiplicative inverse of the element in the field.
   * @param {boolean} [inplace] - unused.
   * @param {*} [_reuse_buf] - unused.
   * @returns {Field} the inverse element (this^{-1} mod f).
   */
  invert(inplace, _reuse_buf) {
    let a = impl.mod(this.bytes, this.mod_bits);
    let p = this.curve.calc_modulus(this.mod_bits);
    // The m=191 field (PB_191) is inverted with the Fermat method; the fast
    // binary-Euclid routine is used for the remaining supported curves.
    if (this.curve.m == 191) {
      impl.inv_slow(this.curve.m, a, this.mod_bits, a);
    } else {
      impl.inv_fast(a, p, a);
    }

    return new Field(a, undefined, this.curve);
  }

  /**
   * Infer the input format from the JS type of a value.
   * @param {string|Uint8Array|Uint32Array} in_value - the value to inspect.
   * @returns {string} "hex", "buf8", or "buf32".
   */
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

  /**
   * Construct a Field from a signed-value representation.
   * @param {*} in_value - the value in format `fmt`.
   * @param {string} fmt - the input format (see constructor).
   * @param {Object} curve - the curve/field parameters.
   * @returns {Field} the constructed element.
   */
  static parse_sign(in_value, fmt, curve) {
    let field = new Field(in_value, fmt, curve);
    return field;
  }
}

const HEX = "0123456789ABCDEF";
/**
 * Parse a big-endian hex string into a little-endian Uint32Array of words.
 * @param {string} in_value - hexadecimal digits (case-insensitive).
 * @param {number} [max_size] - minimum number of words to allocate.
 * @returns {Uint32Array} the packed value.
 */
function from_hex(in_value, max_size) {
  let idx;
  let chr;
  let code;
  let vidx = 0;
  let bpos = 0;
  // 8 hex digits (4 bits each) fill one 32-bit word.
  let size = Math.ceil(in_value.length / 8);
  size = Math.max(size, max_size || size);
  let value = new Uint32Array(size);
  // Walk from the least significant hex digit, packing 4 bits at a time and
  // advancing to the next word every 8 digits.
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

/**
 * Parse a big-endian byte array into a little-endian Uint32Array of words.
 * @param {Uint8Array|number[]} in_value - the bytes, most significant first.
 * @param {number} [max_size] - minimum number of words to allocate.
 * @returns {Uint32Array} the packed value.
 */
function from_u8(in_value, max_size) {
  let vidx = 0;
  let bpos = 0;
  // 4 bytes (8 bits each) fill one 32-bit word.
  let size = Math.ceil(in_value.length / 4);
  size = Math.max(size, max_size || size);
  let value = new Uint32Array(size);
  let idx;
  let code;

  if (in_value.toString() === "[object Uint32Array]") {
    throw new Error("fuck off");
  }

  // Walk from the least significant byte, packing 8 bits at a time and
  // advancing to the next word every 4 bytes.
  for (idx = in_value.length - 1; idx >= 0; idx--) {
    code = in_value[idx];
    bpos = bpos % 4;

    // Normalize signed byte values (e.g. from a signed array) into 0..255.
    if (code < 0) {
      code = 256 + code;
    }
    value[vidx] |= code << (bpos * 8);

    if (bpos === 3) vidx++;
    bpos++;
  }

  return value;
}

/**
 * Replace the arithmetic backend used by Field instances.
 * @param {Object} _impl - a module exposing mul, mod, inv_fast, inv_slow, etc.
 * @returns {void}
 */
function set_impl(_impl) {
  impl = _impl;
}

export default Field;
export { Field, from_hex, from_u8, set_impl };
