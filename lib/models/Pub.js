/*
 * Pub - DSTU 4145 public key model.
 *
 * Wraps a public point Q on a binary-field EC curve and provides DSTU 4145
 * signature verification, point validation, compression, the serialized
 * (0x04-prefixed) public-key encoding, and a hash-based key identifier.
 */
import * as util from "../util.js";
import Field from "../field.js";
import { Buffer } from "buffer";

class Pub {
  /**
   * @param {Curve} p_curve DSTU 4145 curve the key lives on.
   * @param {Object} point_q Public point Q (has x/y field coordinates).
   * @param {*} [compressed] Optional precomputed compressed representation.
   */
  constructor(p_curve, point_q, compressed) {
    this.x = point_q.x;
    this.y = point_q.y;
    this.point = point_q;
    this.curve = p_curve;
    this._cmp = compressed && new Field(compressed, "buf32", this.curve);
    this.type = "Pub";
  }

  /**
   * Compressed public point bytes (memoized).
   * @returns {Buffer} Compressed representation as big-endian bytes.
   */
  compress() {
    if (!this._cmp) {
      this._cmp = this.point.compress();
    }
    return this._cmp.buf8();
  }

  /**
   * Verify a DSTU 4145 signature over a message hash.
   * @param {Buffer|Field} hash_val Message hash.
   * @param {Object|Buffer|string} sign Signature in any supported form.
   * @param {string} [fmt] Signature format; auto-detected when omitted.
   * @returns {boolean} True when the signature is valid.
   */
  verify(hash_val, sign, fmt) {
    if (fmt === undefined) {
      fmt = Pub.detect_sign_format(sign);
    }
    if (Buffer.isBuffer(hash_val)) {
      hash_val = new Field(util.add_zero(hash_val, true), "buf8", this.curve);
    }

    sign = Pub.parse_sign(sign, fmt, this.curve);
    return this.help_verify(hash_val, sign.s, sign.r);
  }

  /**
   * Core DSTU 4145 verification math for signature components s and r.
   * @param {Field} hash_val Message hash mapped into the field.
   * @param {Field} s Signature component s.
   * @param {Field} r Signature component r.
   * @returns {boolean} True when the recomputed r matches.
   */
  help_verify(hash_val, s, r) {
    if (s.is_zero()) {
      throw new Error("Invalid sig component S");
    }
    if (r.is_zero()) {
      throw new Error("Invalid sig component R");
    }

    // s and r must be reduced modulo the group order.
    if (this.curve.order.less(s)) {
      throw new Error("Invalid sig component S");
    }
    if (this.curve.order.less(r) < 0) {
      throw new Error("Invalid sig component R");
    }

    // Reconstruct point R = s*G + r*Q (Q is this public key).
    const mulQ = this.point.mul(r);
    const mulS = this.curve.base.mul(s);
    const pointR = mulS.add(mulQ);

    if (pointR.is_zero()) {
      throw new Error("Invalid sig R point at infinity");
    }

    // r' = truncate( hash * R.x ); signature is valid iff r' == r.
    let r1 = pointR.x.mod_mul(hash_val);
    r1 = this.curve.truncate(r1);

    return r.equals(r1);
  }

  /**
   * Check that the public point is a valid, on-curve point of full order.
   * @returns {boolean} True when Q is non-zero, on the curve, and n*Q = O.
   */
  validate() {
    const pub_q = this.point;
    // n*Q must be the point at infinity for Q to lie in the prime subgroup.
    const pt = pub_q.mul(this.curve.order);

    if (pub_q.is_zero() || !this.curve.contains(pub_q) || !pt.is_zero()) {
      return false;
    }

    return true;
  }

  /**
   * Encode the public key in the DSTU 0x04-tagged, length-prefixed form.
   * @returns {Buffer} Serialized public key (0x04, length, byte-reversed key).
   */
  serialize() {
    const buf = this.compress();
    // Trim to the curve's field byte size, then emit tag + length header.
    const cut = buf.length - Math.ceil(this.curve.m / 8);
    const inverse = Buffer.alloc(buf.length + 2 - cut);

    // Copy compressed key bytes in reversed (little-endian) order.
    for (let i = 2; i < inverse.length; i++) {
      inverse[i] = buf[buf.length + 1 - i];
    }

    inverse[0] = 0x04;
    inverse[1] = buf.length - cut;
    return inverse;
  }

  /**
   * Compute the key identifier: a hash over the serialized public key.
   * @param {Object} algos Algorithm bundle providing hash().
   * @returns {Buffer} Key identifier hash.
   */
  keyid(algos) {
    return algos.hash(this.serialize());
  }

  /**
   * Detect the encoding of raw public key input.
   * @param {*} inp Candidate public key material.
   * @returns {string} "hex" or "raw".
   */
  static detect_format(inp) {
    if (util.is_hex(inp)) {
      return "hex";
    }
    if (inp.buffer !== undefined) {
      return "raw";
    }

    throw new Error("Unknown pubkey format");
  }

  /**
   * Detect a signature's format from its runtime shape.
   * @param {Object|Buffer|string} sign Signature value.
   * @returns {string|undefined} "split" for {s,r}, "short" for bytes/string.
   */
  static detect_sign_format(sign) {
    if (
      sign.hasOwnProperty &&
      Object.prototype.hasOwnProperty.call(sign, "s") &&
      Object.prototype.hasOwnProperty.call(sign, "r")
    ) {
      return "split";
    }
    if (typeof sign === "string" || Buffer.isBuffer(sign)) {
      return "short";
    }
  }

  /**
   * Normalize a signature in any format into Field components {s, r}.
   * @param {Object|Buffer|string} sign Signature value.
   * @param {string} fmt Source format ("short", "le", or "split").
   * @param {Curve} curve Curve used to construct the Field components.
   * @returns {Object} {s, r} as Field instances.
   */
  static parse_sign(sign, fmt, curve) {
    if (fmt === "short") {
      if (!Buffer.isBuffer(sign)) {
        sign = Buffer.from(sign);
      }

      // Validate the 0x04 tag and length byte, then strip the 2-byte header.
      if (sign[0] !== 4 || sign[1] !== sign.length - 2) {
        throw new Error("Broken short sign");
      }
      sign = sign.slice(2);
      fmt = "le";
    }

    if (fmt === "le") {
      // Little-endian payload holds r in the first half, s in the second.
      const len = sign.length;
      const r = sign.slice(0, Math.ceil(len / 2));
      const s = sign.slice(r.length);

      sign = {
        s: util.add_zero(s, true),
        r: util.add_zero(r, true)
      };
      fmt = "split";
    }

    if (fmt === "split") {
      if (typeof sign.s === "string") {
        sign.s = Buffer.from(sign.s);
      }
      if (typeof sign.r === "string") {
        sign.r = Buffer.from(sign.r);
      }

      return {
        s: new Field(sign.s, "buf8", curve),
        r: new Field(sign.r, "buf8", curve)
      };
    }
  }
}

export default Pub;
