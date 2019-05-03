const Field = require("./field.js");
const wnaf = require("./wnaf/index.js");

var Point = function(p_curve, p_x, p_y) {
  const zero = p_curve.zero;

  let ob;

  let coords;

  const add = function(point_1) {
    let a;
    let x0;
    let x1;
    let y0;
    let y1;
    let x2;
    let y2;
    let point_2;
    let lbd;
    let tmp;
    let tmp2;

    a = p_curve.param_a;
    point_2 = new Point(p_curve, zero, zero);

    x0 = ob.x;
    y0 = ob.y;
    x1 = point_1.x;
    y1 = point_1.y;

    if (ob.is_zero()) {
      return point_1;
    }

    if (point_1.is_zero()) {
      return ob;
    }

    if (x0.equals(x1) === false) {
      tmp = y0.add(y1);
      tmp2 = x0.add(x1);
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
    y2 = lbd.mod_mul(x1.add(x2));
    y2.addM(x2);
    y2.addM(y1);

    point_2.x = x2;
    point_2.y = y2;

    return point_2;
  };

  const twice = function() {
    return this.add(this);
  };

  const timesPow2 = function(n) {
    let ret = this;
    while (n--) {
      ret = ret.twice();
    }

    return ret;
  };

  const twicePlus = function(other) {
    return this.twice().add(other);
  };

  const mul = function(param_n) {
    const point_s = new Point(p_curve, zero, zero);

    let point;

    if (param_n.is_zero()) {
      return point_s;
    }

    if (param_n.is_negative()) {
      param_n = param_n.negate();
      point = ob.negate();
    } else {
      point = this;
    }

    return wnaf.mulPos(point, param_n);
  };

  const negate = function() {
    return new Point(p_curve, ob.x, ob.x.add(ob.y));
  };

  const is_zero = function() {
    return ob.x.is_zero() && ob.y.is_zero();
  };

  const expand = function(val) {
    return p_curve.expand(val);
  };

  const compress = function() {
    let x_inv;
    let tmp;
    let ret;
    let trace;

    x_inv = ob.x.invert();
    tmp = x_inv.mod_mul(ob.y);
    trace = tmp.trace();
    ret = ob.x;
    if (trace === 1) {
      ret = ret.setBit(0);
    } else {
      ret = ret.clearBit(0);
    }

    return ret;
  };

  const equals = function(other) {
    return other.x.equals(ob.x) && other.y.equals(ob.y);
  };

  const toString = function() {
    return `<Point x:${ob.x.toString(16)}, y:${ob.y.toString(16)} >`;
  };

  if (p_y === undefined) {
    coords = expand(p_x);
    p_x = coords.x;
    p_y = coords.y;
  }

  ob = {
    add,
    twice,
    timesPow2,
    twicePlus,
    mul,
    is_zero,
    negate,
    expand,
    compress,
    equals,
    toString,
    x: p_x._is_field ? p_x : new Field(p_x, "buf32", p_curve),
    y: p_y._is_field ? p_y : new Field(p_y, "buf32", p_curve),
    _precomp: { pos: [], neg: [] }
  };
  ob._precomp.pos[0] = ob;
  return ob;
};


module.exports = Point;
