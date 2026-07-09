/*
 * Non-adjacent form (NAF) recoding of scalars for elliptic-curve point
 * multiplication. A width-w wNAF represents an integer as a sparse sequence
 * of signed odd digits so that a left-to-right double-and-add pass performs
 * far fewer point additions than a plain binary expansion.
 *
 * Each entry emitted here is packed into a single Int32: the high 16 bits
 * hold the signed digit and the low 16 bits hold the number of zero
 * doublings that precede it (run length), i.e. (digit << 16) | zeroes.
 */
import { shiftRight } from "../gf2m.js";

// Scalar bit-length thresholds that select the wNAF window width (see
// getWindowSize): larger scalars use wider windows to trade precomputation
// for fewer additions.
var DEFAULT_CUTOFFS = [13, 41, 121, 337, 897, 2305];

/**
 * Compute the width-w NAF of a scalar.
 * @param {number} width Window width w (>= 2); width 2 delegates to compactNaf.
 * @param {Field} bigint The scalar to recode (cloned, not mutated by caller).
 * @returns {Int32Array} Packed digits (digit << 16) | zeroes, least-significant first.
 */
function windowNaf(width, bigint) {
  var wnaf, ret_len;
  bigint = bigint.clone();

  if (width === 2) {
    return compactNaf(bigint);
  }

  // Upper bound on the number of non-zero digits produced.
  ret_len = Math.floor(bigint.bitLength() / width + 1);
  wnaf = new Int32Array(ret_len);

  // 2^width and a masbigint and sign bit set accordingly
  // i.e. pow2 = 2^w, masbigint = low-w-bit mask, sign = the window's top bit.
  var pow2 = 1 << width;
  var masbigint = pow2 - 1;
  var sign = pow2 >>> 1;

  var carry = false;
  var length = 0,
    pos = 0;
  var digit, zeroes;

  while (pos <= bigint.bitLength()) {
    // Skip runs of bits that already match the pending carry (they contribute
    // only doublings, no addition).
    if (bigint.testBit(pos) === carry) {
      ++pos;
      continue;
    }

    // Consume the run of zero bits by right-shifting so the next window sits
    // at the bottom of the working value.
    bigint.shiftRightM(pos);

    digit = bigint.bytes[0] & masbigint;

    if (carry) {
      ++digit;
    }

    // If the window's top bit is set, the digit is negative; represent it as
    // digit - 2^width and propagate a carry into the next window. This keeps
    // digits odd and within (-2^(w-1), 2^(w-1)).
    carry = (digit & sign) !== 0;
    if (carry) {
      digit -= pow2;
    }

    zeroes = length > 0 ? pos - 1 : pos;
    wnaf[length++] = (digit << 16) | zeroes;
    pos = width;
  }

  // Reduce the WNAF array to its actual length
  if (wnaf.length > length) {
    wnaf = wnaf.subarray(0, length);
  }

  return wnaf;
}

/**
 * Compute the ordinary (width-2) NAF of a scalar.
 * @param {Field} k The scalar to recode; must have bit length < 2^16.
 * @returns {Int32Array} Packed digits (+/-1 << 16) | zeroes, least-significant first.
 */
function compactNaf(k) {
  if (k.bitLength() >>> 16 != 0) {
    throw new Error("'k' must have bitlength < 2^16");
  }
  if (k.signum() == 0) {
    return new Int32Array(0);
  }

  // Classic NAF trick: bits where 3k and k differ mark the non-zero NAF
  // positions, and k's bit there decides the sign (+1 or -1).
  var _3k = k.shiftLeft(1).add(k);
  var bits = _3k.bitLength();
  var naf = new Int32Array(bits >> 1);

  var diff = _3k.xor(k);

  var highBit = bits - 1,
    length = 0,
    zeroes = 0;
  var i, digit;
  for (i = 1; i < highBit; ++i) {
    if (!diff.testBit(i)) {
      ++zeroes;
      continue;
    }

    digit = k.testBit(i) ? -1 : 1;
    naf[length++] = (digit << 16) | zeroes;
    zeroes = 1;
    ++i;
  }

  naf[length++] = (1 << 16) | zeroes;

  if (naf.length > length) {
    naf = naf.subarray(0, length);
  }

  return naf;
}

/**
 * Pick a wNAF window width from a scalar bit length and a cutoff table.
 * @param {number} bits Bit length of the scalar.
 * @param {number[]} cutoffs Ascending bit-length thresholds.
 * @returns {number} Window width (>= 2): count of cutoffs exceeded, plus 2.
 */
function _getWindowSize(bits, cutoffs) {
  var i,
    cuts = cutoffs.length;

  for (i = 0; i < cuts; ++i) {
    if (bits < cutoffs[i]) {
      break;
    }
  }

  return i + 2;
}

/**
 * Pick a wNAF window width for a scalar using the default cutoff table.
 * @param {number} bits Bit length of the scalar.
 * @returns {number} Window width (2..8 for the default cutoffs).
 */
function getWindowSize(bits) {
  return _getWindowSize(bits, DEFAULT_CUTOFFS);
}

export { getWindowSize, windowNaf, compactNaf };
