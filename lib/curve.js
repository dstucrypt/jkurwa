/* eslint-disable camelcase,no-underscore-dangle,no-bitwise */
const bn = require("asn1.js").bignum;

const Field = require("./field.js");
const wnaf = require("./wnaf/index.js");
const Priv = require("./models/Priv.js");
const Pub = require("./models/Pub");
const standard = require("./standard.js");
const util = require("./util.js");
const random = require("./rand.js");
const Point = require("./point.js");

const H = util.maybeHex;

function fsquad_odd(value, curve) {
  const bitl_m = curve.m;
  const range_to = (bitl_m - 1) / 2;
  const val_a = value.mod();

  let val_z = val_a;

  for (let idx = 1; idx <= range_to; idx += 1) {
    val_z = val_z.mod_sqr().mod_sqr();
    val_z.addM(val_a);
  }

  const val_w = val_z.mod_mul(val_z);
  val_w.addM(val_z);

  if (val_w.equals(val_a)) {
    return val_z;
  }

  throw new Error("squad eq fail");
}

function fsquad(value, curve) {
  let ret;
  if (curve.modulus.testBit(0)) {
    ret = fsquad_odd(value, curve);
  } else {
    throw new Error("only odd modulus is supported :(");
  }

  return ret.mod();
}

class Curve {
  static resolve(def, fmt) {
    if (def.type === "params") {
      return Curve.from_asn1(def.value, fmt);
    }
    if (def.type === "id") {
      return Curve.from_id(def.value);
    }
    throw new Error("Unknown type", def.type);
  }

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

  static from_asn1(curve, fmt) {
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

  static ks_parse(ks) {
    if (ks.type === "trinominal") {
      return [ks.value];
    }
    return [ks.value.k1, ks.value.k2, ks.value.k3];
  }

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
    this.m = (typeof params.m === 'number') ? params.m : params.m.toNumber();
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
    if (params.base.x === undefined) {
      ({ x: base_x, y: base_y } = this.expand(H(params.base, mod_words)));
    } else {
      base_x = H(params.base.x, mod_words);
      base_y = H(params.base.y, mod_words);
    }
    this.set_base(base_x, base_y);
  }

  comp_modulus(m, ks) {
    let modulus = this.one;
    modulus = modulus.setBit(m);
    for (let i = 0; i < ks.length; i += 1) {
      modulus = modulus.setBit(ks[i]);
    }
    return modulus;
  }

  set_base(base_x, base_y) {
    let width = wnaf.getWindowSize(this.m);
    width = Math.max(2, Math.min(16, width));
    this.base = this.point(base_x, base_y);
    wnaf.precomp(this.base, width);
    const cmp = this.base.compress();
    this.expand_cache[cmp.toString()] = this.base;
  }

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

    const k = x.testBit(0);
    x = x.clearBit(0);

    const trace = x.trace();
    if ((trace !== 0 && pa.is_zero()) || (trace === 0 && pa.equals(this.one))) {
      x = x.setBit(0);
    }

    const x2 = x.mod_mul(x);
    y = x2.mod_mul(x);

    if (pa.equals(this.one)) {
      y.addM(x2);
    }

    y.addM(pb);
    const invx2 = x2.invert();

    y = y.mod_mul(invx2);
    y = fsquad(y, this);

    const trace_y = y.trace();

    if ((k === true && trace_y === 0) || (k === false && trace_y !== 0)) {
      y.bytes[0] ^= 1;
    }

    y = y.mod_mul(x);

    return {
      x,
      y
    };
  }

  field(val) {
    return new Field(val.bytes, undefined, this).mod();
  }

  point(px, py) {
    return new Point(this, px, py);
  }

  truncate(value) {
    const bitl_o = this.order.bitLength();

    let xbit = value.bitLength();
    let ret = value;
    while (bitl_o <= xbit) {
      ret = ret.clearBit(xbit - 1);
      xbit = ret.bitLength();
    }
    return ret;
  }

  contains(point) {
    let lh = point.x.add(this.a);
    lh = lh.mod_mul(point.x);
    lh.addM(point.y);
    lh = lh.mod_mul(point.x);
    lh.addM(this.b);
    const y2 = point.y.mod_mul(point.y);
    lh.addM(y2);

    return lh.is_zero();
  }

  rand() {
    const bits = this.order.bitLength();
    const words = Math.ceil(bits / 8);

    let ret;
    do {
      let rand8 = new global.Uint8Array(words);
      rand8 = random(rand8);
      ret = new Field(rand8, "buf8", this);
    } while (this.order.less(ret));

    return ret;
  }

  pkey(inp, fmt) {
    const format = fmt || Priv.detect_format(inp);
    return new Priv(this, new Field(inp, format, this));
  }

  pubkey(inp, input_fmt) {
    let fmt = input_fmt || Pub.detect_format(inp);
    if (fmt === "raw") {
      fmt = "buf32";
    }
    const compressed = new Field(inp, fmt, this);
    const pointQ = this.point(compressed);
    return new Pub(this, pointQ, inp);
  }

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

  keygen() {
    let priv;
    let pub;
    do {
      const rand_d = this.rand();
      priv = new Priv(this, rand_d);
      pub = priv.pub();
    } while (!pub.validate());

    return priv;
  }

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

  calc_modulus() {
    const ret = new global.Uint32Array(this.mod_words);
    ret[0] = 1;

    let word = Math.floor(this.m / 32);
    let bit = this.m % 32;
    ret[word] |= 1 << bit;

    for (let i = 0; i < this.ks.length; i += 1) {
      word = Math.floor(this.ks[i] / 32);
      bit = this.ks[i] % 32;
      ret[word] |= 1 << bit;
    }

    return ret;
  }

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

function pubkey(curve_name, key_data, key_fmt) {
  const curve = Curve.from_id(curve_name);
  return curve.pubkey(key_data, key_fmt);
}

function pkey(curve_name, key_data, key_fmt) {
  const curve = Curve.from_id(curve_name);
  return curve.pkey(key_data, key_fmt);
}

module.exports.Curve = Curve;
module.exports.Field = Field;
module.exports.pkey = pkey;
module.exports.pubkey = pubkey;
module.exports.std_curve = Curve.from_id;
