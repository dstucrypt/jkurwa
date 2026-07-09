/*
 * Windowed non-adjacent form (wNAF) scalar multiplication of an
 * elliptic-curve point. precomp() builds the table of small odd multiples of
 * a base point and mulPos() runs the left-to-right double-and-add loop over
 * the wNAF digits produced by wnaf.js.
 */
import { getWindowSize, windowNaf } from "./wnaf.js";

// Lookup table of bit lengths for byte values 0..255 (bitLengths[n] is the
// index of the highest set bit of n, plus one). Used to decompose the first
// wNAF digit for the doubling-saving optimization in mulPos.
let bitLengths;

bitLengths = new Uint8Array([
  0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
  6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8,
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8
]);

/**
 * Precompute (and cache on the point) the small odd multiples used by wNAF.
 * @param {Point} point Base point; its _precomp/_twice caches are populated.
 * @param {number} width wNAF window width; table holds 2^(width-2) odd multiples.
 * @returns {{pos: Point[], neg: Point[]}} Positive multiples P,3P,5P,... and their negations.
 */
var precomp = function (point, width) {
  var i, len_off, len, ret, rpos, rneg, twice;

  // Number of odd multiples needed is 2^(width-2): P, 3P, 5P, ... up to (2^(w-1)-1)P.
  len_off = width - 2;

  if (len_off < 0) {
    len_off = 0;
  }

  len = 1 << len_off;
  rpos = point._precomp.pos;
  rneg = point._precomp.neg;
  i = rpos.length;

  if (!rneg[0]) {
    rneg[0] = point.negate();
  }

  if (len === 1) {
    return {
      pos: rpos,
      neg: rneg
    };
  }

  // 2P is the common increment between consecutive odd multiples; cache it.
  twice = point._twice || (point._twice = point.twice());

  // Extend the table from where a previous call left off: rpos[i] = (2i+1)P.
  for (; i < len; i++) {
    rpos[i] = twice.add(rpos[i - 1]);
    rneg[i] = rpos[i].negate();
  }

  return {
    pos: rpos,
    neg: rneg
  };
};

/**
 * Multiply an elliptic-curve point by a positive scalar using wNAF.
 * @param {Point} point The base point P.
 * @param {Field} big_k The non-negative scalar k.
 * @returns {Point} The product k*P.
 */
var mulPos = function (point, big_k) {
  var width = getWindowSize(big_k.bitLength());
  width = Math.max(2, Math.min(16, width));

  var precomps = precomp(point, width);
  var ppos = precomps.pos;
  var pneg = precomps.neg;

  var wnaf = windowNaf(width, big_k);

  // Accumulator starts at the point at infinity (identity).
  var R = point.Inf;

  // Iterate wNAF digits from most significant (highest index) down.
  var i = wnaf.length;

  /*
   * NOTE: We try to optimize the first window using the precomputed points to substitute an
   * addition for 2 or more doublings.
   */
  if (i > 1) {
    // Unpack the most significant digit and its trailing zero run.
    var wi = wnaf[--i];
    var digit = wi >> 16,
      zeroes = wi & 0xffff;

    var n = Math.abs(digit);
    var table = digit < 0 ? pneg : ppos;

    // Optimization can only be used for values in the lower half of the table
    if (n << 2 < 1 << width) {
      // Split n*P into the sum of two precomputed table entries so that
      // 'scale' extra doublings can be folded into the trailing-zero run
      // (cheaper than doubling the accumulator later). highest is the index
      // of n's top bit; lowBits is n with that bit removed.
      var highest = bitLengths[n];

      // TODO Get addition/doubling cost ratio from curve and compare to 'scale' to see if worth substituting?
      var scale = width - highest;
      var lowBits = n ^ (1 << (highest - 1));

      var i1 = (1 << (width - 1)) - 1;
      var i2 = (lowBits << scale) + 1;
      R = table[i1 >>> 1].add(table[i2 >>> 1]);

      // The scaled-up split already accounts for 'scale' doublings.
      zeroes -= scale;
    } else {
      R = table[n >>> 1];
    }

    // Apply the pending doublings for the leading digit's zero run.
    R = R.timesPow2(zeroes);
  }

  // Main loop: for each remaining digit, do one twice-plus-add (2R + digit*P)
  // then the doublings for that digit's trailing zero run.
  var wi, digit, n, table, r;
  while (i > 0) {
    wi = wnaf[--i];
    ((digit = wi >> 16), (zeroes = wi & 0xffff));

    n = Math.abs(digit);
    table = digit < 0 ? pneg : ppos;
    r = table[n >>> 1];

    R = R.twicePlus(r);
    R = R.timesPow2(zeroes);
  }

  return R;
};

export { mulPos, precomp };
