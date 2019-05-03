/* eslint-disable camelcase,no-underscore-dangle */
const Field = require("./field.js");
const wnaf = require("./wnaf/index.js");

class Point {
  constructor(curve, input_x, input_y) {
    let p_x; let p_y;
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
    this._precomp = { pos: [this], neg: [] };
  }

  add(point_1) {
    const a = this.curve.param_a;
    const point_2 = new Point(this.curve, this.curve.zero, this.curve.zero);

    const x0 = this.x;
    const y0 = this.y;
    const x1 = point_1.x;
    const y1 = point_1.y;

    if (this.is_zero()) {
      return point_1;
    }

    if (point_1.is_zero()) {
      return this;
    }

    let x2;
    let lbd;
    if (x0.equals(x1) === false) {
      const tmp = y0.add(y1);
      const tmp2 = x0.add(x1);
      lbd = tmp.mod_mul(tmp2.invert());
      x2 = a.add(lbd.mod_mul(lbd));
      x2.addM(lbd);
      x2.addM(x0);
      x2.addM(x1);
    } else {
      if (y1.equals(y0) === false) {
        return point_2;
      }
      if (x1.is_zero()) {
        return point_2;
      }

      lbd = x1.add(point_1.y.mod_mul(point_1.x.invert()));
      x2 = lbd.mod_mul(lbd).add(a);
      x2.addM(lbd);
    }

    const y2 = lbd.mod_mul(x1.add(x2));
    y2.addM(x2);
    y2.addM(y1);

    point_2.x = x2;
    point_2.y = y2;

    return point_2;
  }

  twice() {
    return this.add(this);
  }

  timesPow2(n) {
    let ret = this;
    let left = n;
    while (left) {
      ret = ret.twice();
      left -= 1;
    }

    return ret;
  }

  twicePlus(other) {
    return this.twice().add(other);
  }

  mul(param_n) {
    const point_s = new Point(this.curve, this.curve.zero, this.curve.zero);

    let point = this;
    let value_n = param_n;

    if (param_n.is_zero()) {
      return point_s;
    }

    if (value_n.is_negative()) {
      value_n = param_n.negate();
      point = this.negate();
    }

    return wnaf.mulPos(point, param_n);
  }

  negate() {
    return new Point(this.curve, this.x, this.x.add(this.y));
  }

  is_zero() {
    return this.x.is_zero() && this.y.is_zero();
  }

  compress() {
    const x_inv = this.x.invert();
    const tmp = x_inv.mod_mul(this.y);
    const trace = tmp.trace();
    if (trace === 1) {
      return this.x.setBit(0);
    }
    return this.x.clearBit(0);
  }

  equals(other) {
    return other.x.equals(this.x) && other.y.equals(this.y);
  }

  toString() {
    return `<Point x:${this.x.toString(16)}, y:${this.y.toString(16)} >`;
  }
}

module.exports = Point;
