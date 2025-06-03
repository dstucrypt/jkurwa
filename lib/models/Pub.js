import * as util from "../util.js";
import Field from "../field.js";
import { Buffer } from "buffer";

class Pub {
  constructor(p_curve, point_q, compressed) {
    this.x = point_q.x;
    this.y = point_q.y;
    this.point = point_q;
    this.curve = p_curve;
    this._cmp = compressed && new Field(compressed, "buf32", this.curve);
    this.type = "Pub";
  }

  compress() {
    if (!this._cmp) {
      this._cmp = this.point.compress();
    }
    return this._cmp.buf8();
  }

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

  help_verify(hash_val, s, r) {
    if (s.is_zero()) {
      throw new Error("Invalid sig component S");
    }
    if (r.is_zero()) {
      throw new Error("Invalid sig component R");
    }

    if (this.curve.order.less(s)) {
      throw new Error("Invalid sig component S");
    }
    if (this.curve.order.less(r) < 0) {
      throw new Error("Invalid sig component R");
    }

    const mulQ = this.point.mul(r);
    const mulS = this.curve.base.mul(s);
    const pointR = mulS.add(mulQ);

    if (pointR.is_zero()) {
      throw new Error("Invalid sig R point at infinity");
    }

    let r1 = pointR.x.mod_mul(hash_val);
    r1 = this.curve.truncate(r1);

    return r.equals(r1);
  }

  validate() {
    const pub_q = this.point;
    const pt = pub_q.mul(this.curve.order);

    if (pub_q.is_zero() || !this.curve.contains(pub_q) || !pt.is_zero()) {
      return false;
    }

    return true;
  }

  serialize() {
    const buf = this.compress();
    const cut = buf.length - Math.ceil(this.curve.m / 8);
    const inverse = Buffer.alloc(buf.length + 2 - cut);

    for (let i = 2; i < inverse.length; i++) {
      inverse[i] = buf[buf.length + 1 - i];
    }

    inverse[0] = 0x04;
    inverse[1] = buf.length - cut;
    return inverse;
  }

  keyid(algos) {
    return algos.hash(this.serialize());
  }

  static detect_format(inp) {
    if (util.is_hex(inp)) {
      return "hex";
    }
    if (inp.buffer !== undefined) {
      return "raw";
    }

    throw new Error("Unknown pubkey format");
  }

  static detect_sign_format(sign) {
    if (
      sign.hasOwnProperty &&
      sign.hasOwnProperty("s") &&
      sign.hasOwnProperty("r")
    ) {
      return "split";
    }
    if (typeof sign === "string" || Buffer.isBuffer(sign)) {
      return "short";
    }
  }

  static parse_sign(sign, fmt, curve) {
    if (fmt === "short") {
      if (!Buffer.isBuffer(sign)) {
        sign = Buffer.from(sign);
      }

      if (sign[0] !== 4 || sign[1] !== sign.length - 2) {
        throw new Error("Broken short sign");
      }
      sign = sign.slice(2);
      fmt = "le";
    }

    if (fmt === "le") {
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
