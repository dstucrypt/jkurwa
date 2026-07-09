/* eslint-disable camelcase,no-underscore-dangle */
/*
 * Affine point on a DSTU 4145 elliptic curve y^2 + xy = x^3 + a*x^2 + b over
 * the binary field GF(2^m). Provides the group law (add/double), scalar
 * multiplication via the wNAF package, point negation, and point
 * compression/decompression. All coordinate arithmetic is delegated to Field
 * (GF(2^m) elements); the point at infinity is represented as (0, 0).
 */
import Field from "./field.js";
import * as wnaf from "./wnaf/index.js";

export default class Point {
  /**
   * Build a curve point from coordinates, or decompress from a single x value.
   * @param {Curve} curve Owning curve, supplies field arithmetic and decompression.
   * @param {Field|*} input_x The x coordinate, or a compressed point when input_y is omitted.
   * @param {Field|*} [input_y] The y coordinate; if undefined, input_x is decompressed.
   */
  constructor(curve, input_x, input_y) {
    let p_x;
    let p_y;
    if (input_y === undefined) {
      const coords = curve.expand(input_x);
      p_x = coords.x;
      p_y = coords.y;
    } else {
      p_x = input_x;
      p_y = input_y;
    }

    this.curve = curve;
    this.x = p_x._is_field ? p_x : new Field(p_x, "buf32", this.curve);
    this.y = p_y._is_field ? p_y : new Field(p_y, "buf32", this.curve);
    // Per-point wNAF precomputation cache: positive odd multiples and their
    // negations, seeded with this point as the 1*P entry.
    this._precomp = { pos: [this], neg: [] };
  }

  /**
   * Elliptic-curve group addition of this point and another.
   * @param {Point} point_1 The point to add.
   * @returns {Point} The sum this + point_1.
   */
  add(point_1) {
    const a = this.curve.param_a;
    const point_2 = new Point(this.curve, this.curve.zero, this.curve.zero);

    const x0 = this.x;
    const y0 = this.y;
    const x1 = point_1.x;
    const y1 = point_1.y;

    // Identity rules: adding the point at infinity returns the other operand.
    if (this.is_zero()) {
      return point_1;
    }

    if (point_1.is_zero()) {
      return this;
    }

    let x2;
    let lbd;
    if (x0.equals(x1) === false) {
      // Distinct x: chord addition. Slope lbd = (y0+y1)/(x0+x1) (subtraction
      // is XOR in GF(2^m)), then x2 = a + lbd^2 + lbd + x0 + x1.
      const tmp = y0.add(y1);
      const tmp2 = x0.add(x1);
      lbd = tmp.mod_mul(tmp2.invert());
      x2 = a.add(lbd.mod_mul(lbd));
      x2.addM(lbd);
      x2.addM(x0);
      x2.addM(x1);
    } else {
      // Equal x: either the points are inverses (sum is infinity) or equal
      // (tangent doubling).
      if (y1.equals(y0) === false) {
        return point_2;
      }
      if (x1.is_zero()) {
        return point_2;
      }

      // Doubling: slope lbd = x + y/x, then x2 = lbd^2 + lbd + a.
      lbd = x1.add(point_1.y.mod_mul(point_1.x.invert()));
      x2 = lbd.mod_mul(lbd).add(a);
      x2.addM(lbd);
    }

    // Shared y computation: y2 = lbd*(x1 + x2) + x2 + y1.
    const y2 = lbd.mod_mul(x1.add(x2));
    y2.addM(x2);
    y2.addM(y1);

    point_2.x = x2;
    point_2.y = y2;

    return point_2;
  }

  /**
   * Double this point (add it to itself).
   * @returns {Point} 2*this.
   */
  twice() {
    return this.add(this);
  }

  /**
   * Repeatedly double this point n times.
   * @param {number} n Number of doublings to apply.
   * @returns {Point} (2^n)*this.
   */
  timesPow2(n) {
    let ret = this;
    let left = n;
    while (left) {
      ret = ret.twice();
      left -= 1;
    }

    return ret;
  }

  /**
   * Double this point and add another (2*this + other).
   * @param {Point} other Point to add after doubling.
   * @returns {Point} 2*this + other.
   */
  twicePlus(other) {
    return this.twice().add(other);
  }

  /**
   * Scalar multiplication of this point by n via wNAF.
   * @param {Field} param_n The scalar multiplier.
   * @returns {Point} n*this (the point at infinity when n is zero).
   */
  mul(param_n) {
    const point_s = new Point(this.curve, this.curve.zero, this.curve.zero);

    let point = this;
    let value_n = param_n;

    if (param_n.is_zero()) {
      return point_s;
    }

    // Normalize a negative scalar to (-n)*(-P) so mulPos sees a positive scalar.
    if (value_n.is_negative()) {
      point = this.negate();
    }

    return wnaf.mulPos(point, param_n);
  }

  /**
   * Additive inverse of this point on the curve.
   * @returns {Point} -this, which is (x, x + y) over GF(2^m).
   */
  negate() {
    return new Point(this.curve, this.x, this.x.add(this.y));
  }

  /**
   * Test whether this is the point at infinity (encoded as (0, 0)).
   * @returns {boolean} True if both coordinates are zero.
   */
  is_zero() {
    return this.x.is_zero() && this.y.is_zero();
  }

  /**
   * Point compression: return x with its low bit set to the recovery parity.
   * @returns {Field} x carrying the compressed-point tag bit in position 0.
   */
  compress() {
    // The trace of y/x selects which of the two possible y values is meant;
    // store it in x's least significant bit (which x itself never uses here).
    const x_inv = this.x.invert();
    const tmp = x_inv.mod_mul(this.y);
    const trace = tmp.trace();
    if (trace === 1) {
      return this.x.setBit(0);
    }
    return this.x.clearBit(0);
  }

  /**
   * Value equality against another point.
   * @param {Point} other Point to compare with.
   * @returns {boolean} True when both coordinates match.
   */
  equals(other) {
    return other.x.equals(this.x) && other.y.equals(this.y);
  }

  /**
   * Human-readable hex representation of this point.
   * @returns {string} Debug string of the form "<Point x:.., y:.. >".
   */
  toString() {
    return `<Point x:${this.x.toString(16)}, y:${this.y.toString(16)} >`;
  }
}
