/*jslint plusplus: true, bitwise: true */
import { from_hex, from_u8 } from "./field.js";

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

function invert(u8) {
  /*
   * Invert should mask number of "unsed" bits from input.
   * Hoever this bits shold be zeroes and it's safe to
   * ignore them.
   *  mask = 0xFF >>> unused;
   *  */
  let cr,
    ret = [];
  for (i = u8.length - 1; i >= 0; i--) {
    cr = u8[i];
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

function BIG_BE(inp) {
  return from_u8(inp);
}

function BIG_LE(inp) {
  return from_u8(Array.prototype.slice.call(inp, 0).reverse());
}

/*
 * Construct big number from inverted bit string.
 * This is different from LE as not bits should be
 * inverted as well as bytes.
 */
function BIG_INVERT(inp) {
  return add_zero(invert(inp));
}

function maybeHex(inp, pad) {
  let tmp, ret;
  if (typeof inp === "number") {
    ret = [0, inp];
  }

  if (typeof inp === "string") {
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

function strFromUtf8(ab) {
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
