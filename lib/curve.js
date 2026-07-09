/* eslint-disable camelcase,no-underscore-dangle,no-bitwise */
/*
 * DSTU 4145 elliptic curve over the binary field GF(2^m) in polynomial basis.
 * A Curve bundles the field parameters (reduction polynomial m/ks, curve
 * coefficients a and b, base point, group order and cofactor) and offers the
 * operations built on them: point decompression (expand), on-curve testing,
 * random scalar/key generation, public/private key construction, and
 * serialization to/from the ASN.1 parameter structures used in certificates
 * and key containers. Named standard curves are resolved through standard.js.
 */
import asn1 from "asn1.js";

import Field from "./field.js";
import * as wnaf from "./wnaf/index.js";
import Priv from "./models/Priv.js";
import Pub from "./models/Pub.js";
import * as standard from "./standard.js";
import * as util from "./util.js";
import random from "./rand.js";
import Point from "./point.js";

const H = util.maybeHex;
const bn = asn1.bignum;

/**
 * Solve z^2 + z = value in GF(2^m) for odd m (half-trace method).
 * @param {Field} value Right-hand side; must have trace 0 for a solution to exist.
 * @param {Curve} curve Curve providing the field degree m.
 * @returns {Field} A root z of z^2 + z = value.
 * @throws {Error} If no consistent solution is found ("squad eq fail").
 */
function fsquad_odd(value, curve) {
  const bitl_m = curve.m;
  const range_to = (bitl_m - 1) / 2;
  const val_a = value.mod();

  let val_z = val_a;

  // Half-trace: z = sum of a^(2^(2i)) for i in [0, (m-1)/2], built iteratively.
  for (let idx = 1; idx <= range_to; idx += 1) {
    val_z = val_z.mod_sqr().mod_sqr();
    val_z.addM(val_a);
  }

  // Consistency check: z^2 + z must equal the input (compared after >>1).
  const val_w = val_z.mod_mul(val_z);
  val_w.addM(val_z);

  val_a.shiftRightM(1);
  val_w.shiftRightM(1);

  if (val_w.equals(val_a)) {
    return val_z;
  }

  throw new Error("squad eq fail");
}

/**
 * Solve the quadratic z^2 + z = value in GF(2^m).
 * @param {Field} value Right-hand side of the quadratic.
 * @param {Curve} curve Curve whose reduction polynomial defines the field.
 * @returns {Field} The reduced root z.
 * @throws {Error} If the field has an even modulus (unsupported).
 */
function fsquad(value, curve) {
  let ret;
  if (curve.modulus.testBit(0)) {
    ret = fsquad_odd(value, curve);
  } else {
    throw new Error("only odd modulus is supported :(");
  }

  return ret.mod();
}

export default class Curve {
  /**
   * Resolve a curve descriptor (explicit params or a named id) into a Curve.
   * @param {{type: string, value: *}} def Descriptor: type "params" or "id".
   * @param {string} [fmt] Byte order hint for param decoding ("cert" for little-endian).
   * @returns {Curve} The resolved curve.
   * @throws {Error} On an unknown descriptor type.
   */
  static resolve(def, fmt) {
    // When only known curves are allowed, map explicit params onto the
    // standard curve of matching field degree instead of trusting them.
    if (def.type === "params" && Curve.only_known) {
      def = { type: "id", value: "DSTU_PB_" + def.value.p.param_m };
    }
    if (def.type === "params") {
      return Curve.from_asn1(def.value, fmt);
    }
    if (def.type === "id") {
      return Curve.from_id(def.value);
    }
    throw new Error("Unknown type", def.type);
  }

  /**
   * Look up (and memoize) a standard curve by name.
   * @param {string} curve_name Standard curve identifier, e.g. "DSTU_PB_257".
   * @returns {Curve} The cached or newly built curve.
   * @throws {Error} If no standard curve has that name.
   */
  static from_id(curve_name) {
    if (standard.cache[curve_name]) {
      return standard.cache[curve_name];
    }

    if (!standard[curve_name]) {
      throw new Error("Curve with such name was not defined");
    }
    const curve = new Curve(standard[curve_name]);
    standard.cache[curve_name] = curve;

    return curve;
  }

  /**
   * Build a Curve from a decoded ASN.1 parameter structure.
   * @param {Object} curve ASN.1 params (field, coefficients, order, base point).
   * @param {string} [fmt] "cert" selects little-endian byte order for coordinates.
   * @returns {Curve} The constructed curve.
   */
  static from_asn1(curve, fmt) {
    // Certificates encode field elements little-endian; other containers big-endian.
    const big = fmt === "cert" ? util.BIG_LE : util.BIG_BE;

    return new Curve({
      m: curve.p.param_m,
      ks: Curve.ks_parse(curve.p.ks),
      a: [curve.param_a],
      b: big(curve.param_b),
      order: util.BIG_BE(curve.order.toArray()),
      kofactor: [2],
      base: big(curve.bp)
    });
  }

  /**
   * Normalize an ASN.1 reduction-polynomial descriptor to an array of exponents.
   * @param {{type: string, value: *}} ks Trinomial (single k) or pentanomial (k1,k2,k3).
   * @returns {number[]} The middle-term exponents of the reduction polynomial.
   */
  static ks_parse(ks) {
    if (ks.type === "trinominal") {
      return [ks.value];
    }
    return [ks.value.k1, ks.value.k2, ks.value.k3];
  }

  /**
   * Construct a curve from raw parameters, precomputing field temporaries and the base point.
   * @param {Object} params Field degree m, ks exponents, coefficients a/b, order, cofactor, base.
   */
  constructor(params) {
    this.expand_cache = {};

    const mod_words = Math.ceil(params.m / 32);

    this.mod_tmp = new Uint32Array(mod_words + mod_words + 4);
    this.inv_tmp1 = new Uint32Array(mod_words);
    this.inv_tmp2 = new Uint32Array(mod_words);
    this.order = H(params.order, mod_words);
    this.kofactor = H(params.kofactor);
    this.param_a = H(params.a, mod_words);
    this.param_b = H(params.b, mod_words);
    this.m = typeof params.m === "number" ? params.m : params.m.toNumber();
    this.ks = params.ks;
    this.mod_words = mod_words;
    this.zero = new Field([0], "buf32", this);
    this.one = new Field("1", "hex", this);
    this.modulus = this.comp_modulus(params.m, params.ks);
    this.mod_bits = new Uint32Array([this.m].concat(this.ks, [0]));
    this.param_a = new Field(this.param_a, "buf32", this);
    this.param_b = new Field(this.param_b, "buf32", this);
    this.a = this.param_a;
    this.b = this.param_b;
    this.order = new Field(this.order, "buf32", this);
    this.kofactor = new Field(this.kofactor, "buf32", this);

    let base_x;
    let base_y;
    // Base point may be supplied compressed (single value) or as explicit x/y.
    if (params.base.x === undefined) {
      ({ x: base_x, y: base_y } = this.expand(H(params.base, mod_words)));
    } else {
      base_x = H(params.base.x, mod_words);
      base_y = H(params.base.y, mod_words);
    }
    this.set_base(base_x, base_y);
  }

  /**
   * Build the field reduction polynomial as a Field with the m and ks bits set.
   * @param {number} m Degree of the extension field GF(2^m).
   * @param {number[]} ks Middle-term exponents of the reduction polynomial.
   * @returns {Field} The polynomial x^m + ... + 1 as a Field bitmask.
   */
  comp_modulus(m, ks) {
    let modulus = this.one;
    modulus = modulus.setBit(m);
    for (let i = 0; i < ks.length; i += 1) {
      modulus = modulus.setBit(ks[i]);
    }
    return modulus;
  }

  /**
   * Set the generator point and warm the wNAF precomputation and decompression caches.
   * @param {Field} base_x X coordinate of the base point.
   * @param {Field} base_y Y coordinate of the base point.
   */
  set_base(base_x, base_y) {
    let width = wnaf.getWindowSize(this.m);
    width = Math.max(2, Math.min(16, width));
    this.base = this.point(base_x, base_y);
    // Precompute odd multiples of the generator once, since it is reused heavily.
    wnaf.precomp(this.base, width);
    const cmp = this.base.compress();
    this.expand_cache[cmp.toString()] = this.base;
  }

  /**
   * Decompress a point from its x coordinate (with parity bit) to full (x, y).
   * @param {Field|string} val Compressed x value; low bit carries the y parity.
   * @returns {{x: Field, y: Field}|Point} The recovered coordinates (or cached point).
   */
  expand(val) {
    const pa = this.a;

    const pb = this.b;

    let x;
    let y;

    if (typeof val === "string") {
      x = new Field(val, "hex", this);
    } else {
      x = val;
    }
    x = x._is_field ? x : new Field(x, "buf32", this);

    // Special case x = 0: the curve equation gives y = sqrt(b) = b (in GF(2^m)).
    if (x.is_zero()) {
      return {
        x,
        y: pb.mod_mul(pb)
      };
    }

    const cached = this.expand_cache[x.toString()];
    if (cached !== undefined) {
      return cached;
    }

    // Extract the stored parity bit k, then clear it to recover the true x.
    const k = x.testBit(0);
    x = x.clearBit(0);

    // Restore the low bit according to the trace/coefficient relationship used
    // by the DSTU compression scheme.
    const trace = x.trace();
    if ((trace !== 0 && pa.is_zero()) || (trace === 0 && pa.equals(this.one))) {
      x = x.setBit(0);
    }

    // Form the quadratic in beta = y/x: solve beta^2 + beta = x + a + b/x^2.
    const x2 = x.mod_mul(x);
    y = x2.mod_mul(x);

    if (pa.equals(this.one)) {
      y.addM(x2);
    }

    y.addM(pb);
    const invx2 = x2.invert();

    y = y.mod_mul(invx2);
    y = fsquad(y, this);

    // Pick the root whose parity matches the stored bit k; the two roots differ
    // in their least significant bit.
    const trace_y = y.trace();

    if ((k === true && trace_y === 0) || (k === false && trace_y !== 0)) {
      y.bytes[0] ^= 1;
    }

    // Convert beta back to y = beta * x.
    y = y.mod_mul(x);

    return {
      x,
      y
    };
  }

  /**
   * Wrap raw bytes as a reduced field element of this curve.
   * @param {Field} val Source carrying the bytes to reinterpret.
   * @returns {Field} The value reduced modulo the field polynomial.
   */
  field(val) {
    return new Field(val.bytes, undefined, this).mod();
  }

  /**
   * Construct a point on this curve.
   * @param {Field|*} px X coordinate, or a compressed point when py is omitted.
   * @param {Field|*} [py] Y coordinate.
   * @returns {Point} The point.
   */
  point(px, py) {
    return new Point(this, px, py);
  }

  /**
   * Truncate a value to fewer than the order's bit length (DSTU field-element reduction).
   * @param {Field} value Value to shorten by clearing high bits.
   * @returns {Field} A value whose bit length is below the group order's.
   */
  truncate(value) {
    const bitl_o = this.order.bitLength();

    let xbit = value.bitLength();
    let ret = value;
    // Clear the top bit until the value is strictly shorter than the order.
    while (bitl_o <= xbit) {
      ret = ret.clearBit(xbit - 1);
      xbit = ret.bitLength();
    }
    return ret;
  }

  /**
   * Test whether a point satisfies this curve's equation.
   * @param {Point} point The point to check.
   * @returns {boolean} True if the point lies on the curve.
   */
  contains(point) {
    // Evaluate (x+a)*x*x + b + y^2 + x*y; equals 0 iff y^2 + xy = x^3 + a*x^2 + b.
    let lh = point.x.add(this.a);
    lh = lh.mod_mul(point.x);
    lh.addM(point.y);
    lh = lh.mod_mul(point.x);
    lh.addM(this.b);
    const y2 = point.y.mod_mul(point.y);
    lh.addM(y2);

    return lh.is_zero();
  }

  /**
   * Generate a uniform random field element below the group order.
   * @returns {Field} A random scalar in [0, order).
   */
  rand() {
    const bits = this.order.bitLength();
    const words = Math.ceil(bits / 8);

    let ret;
    // Rejection sampling: redraw until the value is below the order.
    do {
      let rand8 = new global.Uint8Array(words);
      rand8 = random(rand8);
      ret = new Field(rand8, "buf8", this);
    } while (this.order.less(ret));

    return ret;
  }

  /**
   * Build a private key on this curve from an input value.
   * @param {*} inp Private scalar in some encoding.
   * @param {string} [fmt] Explicit input format; auto-detected when omitted.
   * @returns {Priv} The private key object.
   */
  pkey(inp, fmt) {
    const format = fmt || Priv.detect_format(inp);
    return new Priv(this, new Field(inp, format, this));
  }

  /**
   * Build a public key on this curve from an input value.
   * @param {*} inp Public key data (compressed point or coordinates).
   * @param {string} [input_fmt] Explicit input format; auto-detected when omitted.
   * @returns {Pub} The public key object.
   */
  pubkey(inp, input_fmt) {
    let fmt = input_fmt || Pub.detect_format(inp);
    if (fmt === "raw") {
      fmt = "buf32";
    }
    const compressed = new Field(inp, fmt, this);
    const pointQ = this.point(compressed);
    return new Pub(this, pointQ, inp);
  }

  /**
   * Structural equality against another curve.
   * @param {Curve} other Curve to compare with.
   * @returns {boolean} True if coefficients, order, modulus and base point all match.
   */
  equals(other) {
    const for_check = ["a", "b", "order", "modulus"];
    for (let i = 0; i < for_check.length; i += 1) {
      const attr = for_check[i];
      if (!this[attr].equals(other[attr])) {
        return false;
      }
    }

    return this.base.equals(other.base);
  }

  /**
   * Generate a valid key pair on this curve.
   * @returns {Priv} A private key whose derived public key passes validation.
   */
  keygen() {
    let priv;
    let pub;
    // Retry until the random scalar yields a public key that validates.
    do {
      const rand_d = this.rand();
      priv = new Priv(this, rand_d);
      pub = priv.pub();
    } while (!pub.validate());

    return priv;
  }

  /**
   * Serialize this curve to the ASN.1 parameter structure.
   * @returns {Object} Field/coefficient/order/base-point struct for encoding.
   */
  as_struct() {
    let ks_p;
    if (this.ks.length === 1) {
      ks_p = {
        type: "trinominal",
        value: this.ks[0]
      };
    } else {
      ks_p = this.ks;
      ks_p = {
        type: "pentanominal",
        value: { k1: ks_p[0], k2: ks_p[1], k3: ks_p[2] }
      };
    }
    return {
      p: {
        param_m: this.m,
        ks: ks_p
      },
      param_a: this.param_a.bytes[0],
      param_b: this.param_b.le(),
      order: new bn.BN(this.order.buf8(), 8),
      bp: this.base.compress().le()
    };
  }

  /**
   * Compute the reduction polynomial as a packed 32-bit word array.
   * @returns {Uint32Array} Bits set at positions 0, m and each ks exponent.
   */
  calc_modulus() {
    const ret = new global.Uint32Array(this.mod_words);
    ret[0] = 1;

    // Set the x^m term.
    let word = Math.floor(this.m / 32);
    let bit = this.m % 32;
    ret[word] |= 1 << bit;

    // Set each middle-term bit of the trinomial/pentanomial.
    for (let i = 0; i < this.ks.length; i += 1) {
      word = Math.floor(this.ks[i] / 32);
      bit = this.ks[i] % 32;
      ret[word] |= 1 << bit;
    }

    return ret;
  }

  /**
   * Map this curve's field degree to its DSTU numeric curve id.
   * @returns {number|undefined} Index 0..9 for a known degree, else undefined.
   */
  curve_id() {
    return {
      163: 0,
      167: 1,
      173: 2,
      179: 3,
      191: 4,
      233: 5,
      257: 6,
      307: 7,
      367: 8,
      431: 9
    }[this.m];
  }

  /**
   * Human-readable standard name of this curve.
   * @returns {string|undefined} Name like "DSTU_PB_257", or undefined if unknown.
   */
  name() {
    return [
      "DSTU_PB_163",
      "DSTU_PB_167",
      "DSTU_PB_173",
      "DSTU_PB_179",
      "DSTU_PB_191",
      "DSTU_PB_233",
      "DSTU_PB_257",
      "DSTU_PB_307",
      "DSTU_PB_367",
      "DSTU_PB_431"
    ][this.curve_id()];
  }
}

/**
 * Build a public key on a named standard curve.
 * @param {string} curve_name Standard curve identifier.
 * @param {*} key_data Public key data.
 * @param {string} [key_fmt] Explicit input format.
 * @returns {Pub} The public key object.
 */
function pubkey(curve_name, key_data, key_fmt) {
  const curve = Curve.from_id(curve_name);
  return curve.pubkey(key_data, key_fmt);
}

/**
 * Build a private key on a named standard curve.
 * @param {string} curve_name Standard curve identifier.
 * @param {*} key_data Private key data.
 * @param {string} [key_fmt] Explicit input format.
 * @returns {Priv} The private key object.
 */
function pkey(curve_name, key_data, key_fmt) {
  const curve = Curve.from_id(curve_name);
  return curve.pkey(key_data, key_fmt);
}

/**
 * Resolve a standard curve by id.
 * @param {string} id Standard curve identifier.
 * @returns {Curve} The named curve.
 */
const std_curve = id => Curve.from_id(id);

export { Curve, Field, pkey, pubkey, std_curve };
