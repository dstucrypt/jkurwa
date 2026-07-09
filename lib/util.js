/*jslint plusplus: true, bitwise: true */
/*
 * Generic byte/hex helper utilities used across the library.
 *
 * Provides conversions between raw byte arrays and big-number field
 * elements, plus small primitives for building DSTU 4145 EC values from
 * different byte encodings (big-endian, little-endian, bit-inverted) and
 * for parsing/normalizing hex input.
 */
import { from_hex, from_u8 } from "./field.js";

/**
 * Prepend (or append) a zero byte so an unsigned value is not misread as
 * negative, optionally reversing to little-endian byte order.
 * @param {Uint8Array|Array|{toBuffer:function}} u8 - source bytes (or an object exposing toBuffer()).
 * @param {boolean} [reorder] - when true, append the zero and reverse (produce LE); otherwise prepend the zero.
 * @returns {number[]} byte array with the padding zero applied.
 */
function add_zero(u8, reorder) {
  let ret = [],
    i;

  if (u8.toBuffer !== undefined) {
    u8 = u8.toBuffer();
  }

  if (reorder !== true) {
    ret.push(0);
  }
  for (i = 0; i < u8.length; i++) {
    ret.push(u8[i]);
  }

  if (reorder === true) {
    ret.push(0);
    ret = ret.reverse();
  }
  return ret;
}

/**
 * Reverse both byte order and the bit order within every byte.
 * @param {Uint8Array|Array} u8 - source bytes.
 * @returns {number[]} bytes in reversed order, each byte bit-reversed.
 */
function invert(u8) {
  /*
   * Invert should mask number of "unsed" bits from input.
   * Hoever this bits shold be zeroes and it's safe to
   * ignore them.
   *  mask = 0xFF >>> unused;
   *  */
  let cr,
    ret = [];
  for (let i = u8.length - 1; i >= 0; i--) {
    cr = u8[i];
    // Reverse the 8 bits of the byte: bit k is moved to bit 7-k by shifting
    // each bit to its mirror position and masking to keep only that bit.
    cr =
      (cr >> 7) |
      ((cr >> 5) & 2) |
      ((cr >> 3) & 4) |
      ((cr >> 1) & 8) |
      ((cr << 1) & 16) |
      ((cr << 3) & 32) |
      ((cr << 5) & 64) |
      ((cr << 7) & 128);
    ret.push(cr);
  }

  return ret;
}

const HEX_REGEXP = /^[A-Fa-f0-9]+$/;

/**
 * Report whether a value is a string made up entirely of hex digits.
 * @param {*} inp - value to test.
 * @returns {boolean} true if inp is a non-empty hex string.
 */
function is_hex(inp) {
  let res;

  if (typeof inp !== "string") {
    return false;
  }

  res = inp.match(HEX_REGEXP);
  if (res === null) {
    return false;
  }

  return res.length > 0;
}

/**
 * Build a big number from big-endian bytes.
 * @param {Uint8Array|Array} inp - big-endian bytes.
 * @returns {*} big-number field element.
 */
function BIG_BE(inp) {
  return from_u8(inp);
}

/**
 * Build a big number from little-endian bytes (bytes reversed to BE first).
 * @param {Uint8Array|Array} inp - little-endian bytes.
 * @returns {*} big-number field element.
 */
function BIG_LE(inp) {
  return from_u8(Array.prototype.slice.call(inp, 0).reverse());
}

/*
 * Construct big number from inverted bit string.
 * This is different from LE as not bits should be
 * inverted as well as bytes.
 */
/**
 * Build a big number from a bit-inverted byte string.
 * @param {Uint8Array|Array} inp - bytes to invert (bit and byte order).
 * @returns {number[]} zero-padded inverted byte array.
 */
function BIG_INVERT(inp) {
  return add_zero(invert(inp));
}

/**
 * Coerce mixed input (number, hex/spaced string, or byte array) into a
 * Uint32Array, optionally zero-padding the tail.
 * @param {number|string|Array|Uint8Array} inp - value to normalize.
 * @param {number} [pad] - number of trailing zero words to append.
 * @returns {Uint32Array} normalized word array.
 */
function maybeHex(inp, pad) {
  let tmp, ret;
  if (typeof inp === "number") {
    ret = [0, inp];
  }

  if (typeof inp === "string") {
    // Strip spaces so grouped hex like "AB CD" is accepted before parsing.
    tmp = inp.replace(/ /g, "");
    if (is_hex(tmp)) {
      return from_hex(tmp, pad);
    }
  }

  if (!ret) {
    ret = inp;
  }

  if (pad) {
    if (!ret.push) {
      ret = Array.prototype.slice.call(inp, 0);
    }
    while (pad--) {
      ret.push(0);
    }
  }

  return new Uint32Array(ret);
}

/**
 * Decode a byte array of UTF-8 data into a JS string.
 * @param {Uint8Array|Array} ab - UTF-8 encoded bytes.
 * @returns {string} decoded string.
 */
function strFromUtf8(ab) {
  // escape() turns the raw byte-per-char string into %XX escapes, then
  // decodeURIComponent reinterprets those bytes as UTF-8 multibyte sequences.
  return decodeURIComponent(escape(String.fromCharCode.apply(null, ab)));
}

export {
  add_zero,
  is_hex,
  invert,
  BIG_BE,
  BIG_LE,
  BIG_INVERT,
  maybeHex,
  strFromUtf8
};
