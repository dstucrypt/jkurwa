/* jslint plusplus: true */
/* jslint bitwise: true */

const Field = require("./field.js");
const bn = require("asn1.js").bignum;
const wnaf = require("./wnaf/index.js");
const Priv = require("./models/Priv.js");
const Pub = require("./models/Pub");
const standard = require("./standard.js");
const util = require("./util.js");
const random = require("./rand.js");
const Point = require("./point.js");

const H = util.maybeHex;

const fsquad_odd = function(value, curve) {
  const bitl_m = curve.m;
  const range_to = (bitl_m - 1) / 2;
  const val_a = value.mod();

  let val_z = val_a;
  let val_w;

  for (let idx = 1; idx <= range_to; idx++) {
    val_z = val_z.mod_sqr().mod_sqr();
    val_z.addM(val_a);
  }

  val_w = val_z.mod_mul(val_z);
  val_w.addM(val_z);

  if (val_w.equals(val_a)) {
    return val_z;
  }

  throw new Error("squad eq fail");
};
const fsquad = function(value, curve) {
  let ret;
  if (curve.modulus.testBit(0)) {
    ret = fsquad_odd(value, curve);
  } else {
    throw new Error("only odd modulus is supported :(");
  }

  return ret.mod();
};

const std_curve = function(curve_name) {
  if (standard.cache.hasOwnProperty(curve_name)) {
    return standard.cache[curve_name];
  }

  if (!standard.hasOwnProperty(curve_name)) {
    throw new Error("Curve with such name was not defined");
  }
  const curve = new Curve(standard[curve_name]);
  standard.cache[curve_name] = curve;

  return curve;
};

const pubkey = function(curve_name, key_data, key_fmt) {
  const curve = std_curve(curve_name);
  return curve.pubkey(key_data, key_fmt);
};

const pkey = function(curve_name, key_data, key_fmt) {
  const curve = std_curve(curve_name);
  return curve.pkey(key_data, key_fmt);
};


const ks_parse = function(ks) {
  if (ks.type === "trinominal") {
    return [ks.value];
  }
  return [ks.value.k1, ks.value.k2, ks.value.k3];
};

const from_asn1 = function(curve, fmt) {
  const big = fmt === "cert" ? util.BIG_LE : util.BIG_BE;

  return new Curve({
    m: curve.p.param_m,
    ks: ks_parse(curve.p.ks),
    a: [curve.param_a],
    b: big(curve.param_b),
    order: util.BIG_BE(curve.order.toArray()),
    kofactor: [2],
    base: big(curve.bp)
  });
};

var Curve = function(params, param_b, m, ks, base, order, kofactor) {
  if (params.base === undefined) {
    params = {
      param_a: params,
      param_b,
      m,
      ks,
      base,
      order,
      kofactor
    };
  }

  this.expand_cache = {};

  const mod_words = Math.ceil(params.m / 32);

  this.mod_tmp = new Uint32Array(mod_words + mod_words + 4);
  this.inv_tmp1 = new Uint32Array(mod_words);
  this.inv_tmp2 = new Uint32Array(mod_words);
  this.order = H(params.order, mod_words);
  this.kofactor = H(params.kofactor);
  this.param_a = H(params.a, mod_words);
  this.param_b = H(params.b, mod_words);
  this.param_m = params.m;
  this.m = params.m;
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

  if (params.base.x === undefined) {
    params.base = this.expand(H(params.base, mod_words));
  } else {
    params.base.x = H(params.base.x, mod_words);
    params.base.y = H(params.base.y, mod_words);
  }
  this.set_base(params.base.x, params.base.y);
};

Curve.prototype.comp_modulus = function(m, ks) {
  let modulus = this.one;
  modulus = modulus.setBit(m);
  for (let i = 0; i < ks.length; i++) {
    modulus = modulus.setBit(ks[i]);
  }
  return modulus;
};

Curve.prototype.set_base = function(base_x, base_y) {
  let cmp;
  let width;
  width = wnaf.getWindowSize(this.m);
  width = Math.max(2, Math.min(16, width));
  this.base = this.point(base_x, base_y);
  wnaf.precomp(this.base, width);
  cmp = this.base.compress();
  this.expand_cache[cmp.toString()] = this.base;
};

Curve.prototype.expand = function(val) {
  const pa = this.a;

  const pb = this.b;

  let x2;

  let y;

  let k;

  let cached;

  let trace;

  let trace_y;

  if (typeof val === "string") {
    val = new Field(val, "hex", this);
  }
  val = val._is_field ? val : new Field(val, "buf32", this);

  if (val.is_zero()) {
    return {
      x: val,
      y: pb.mod_mul(pb)
    };
  }

  cached = this.expand_cache[val.toString()];
  if (cached !== undefined) {
    return cached;
  }

  k = val.testBit(0);
  val = val.clearBit(0);

  trace = val.trace();
  if ((trace !== 0 && pa.is_zero()) || (trace === 0 && pa.equals(this.one))) {
    val = val.setBit(0);
  }

  x2 = val.mod_mul(val);
  y = x2.mod_mul(val);

  if (pa.equals(this.one)) {
    y.addM(x2);
  }

  y.addM(pb);
  x2 = x2.invert();

  y = y.mod_mul(x2);
  y = fsquad(y, this);

  trace_y = y.trace();

  if ((k === true && trace_y === 0) || (k === false && trace_y !== 0)) {
    y.bytes[0] ^= 1;
  }

  y = y.mod_mul(val);

  return {
    x: val,
    y
  };
};

Curve.prototype.field = function(val) {
  return new Field(val.bytes, undefined, this).mod();
};

Curve.prototype.point = function(px, py) {
  return new Point(this, px, py);
};

Curve.prototype.truncate = function(value) {
  const bitl_o = this.order.bitLength();

  let xbit = value.bitLength();

  while (bitl_o <= xbit) {
    value = value.clearBit(xbit - 1);
    xbit = value.bitLength();
  }
  return value;
};

Curve.prototype.contains = function(point) {
  let lh;
  let y2;
  lh = point.x.add(this.a);
  lh = lh.mod_mul(point.x);
  lh.addM(point.y);
  lh = lh.mod_mul(point.x);
  lh.addM(this.b);
  y2 = point.y.mod_mul(point.y);
  lh.addM(y2);

  return lh.is_zero();
};

Curve.prototype.rand = function() {
  let bits;
  let words;
  let ret;
  let rand8;

  while (true) {
    bits = this.order.bitLength();
    words = Math.ceil(bits / 8);
    rand8 = new global.Uint8Array(words);
    rand8 = random(rand8);
    ret = new Field(rand8, "buf8", this);

    if (!this.order.less(ret)) {
      return ret;
    }
  }
};

Curve.prototype.pkey = function(inp, fmt) {
  const format = fmt || Priv.detect_format(inp);
  return new Priv(this, new Field(inp, format, this));
};

Curve.prototype.pubkey = function(inp, fmt) {
  let pointQ;
  if (fmt === undefined) {
    fmt = Pub.detect_format(inp);
  }

  if (fmt === "hex") {
    inp = new Field(inp, "hex", this);
    fmt = "field";
  }

  if (fmt === "buf8" || fmt === "buf32") {
    inp = new Field(inp, fmt, this);
    fmt = "field";
  }

  if (fmt === "raw") {
    inp = new Field(inp, "buf32", this);
    fmt = "field";
  }

  pointQ = this.point(inp);
  return new Pub(this, pointQ, inp);
};

Curve.prototype.equals = function(other) {
  const for_check = ["a", "b", "order", "modulus"];
  for (let i = 0; i < for_check.length; i++) {
    let attr = for_check[i];
    if (!this[attr].equals(other[attr])) {
      return false;
    }
  }

  return this.base.equals(other.base);
};

Curve.prototype.keygen = function() {
  let rand_d;
  let priv;
  let pub;
  while (true) {
    rand_d = this.rand();
    priv = new Priv(this, rand_d);
    pub = priv.pub();
    if (pub.validate()) {
      return priv;
    }
  }
};

Curve.prototype.as_struct = function() {
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
};

Curve.prototype.calc_modulus = function() {
  const ret = new global.Uint32Array(this.mod_words);
  ret[0] = 1;

  let word = Math.floor(this.m / 32);
  let bit = this.m % 32;
  ret[word] |= 1 << bit;

  for (let i = 0; i < this.ks.length; i++) {
    word = Math.floor(this.ks[i] / 32);
    bit = this.ks[i] % 32;
    ret[word] |= 1 << bit;
  }

  return ret;
};

Curve.prototype.curve_id = function() {
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
};

Curve.prototype.name = function() {
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
};

Curve.resolve = function(def, fmt) {
  if (def.type === "params") {
    return Curve.from_asn1(def.value, fmt);
  }
  if (def.type === "id") {
    return std_curve(def.value);
  }
};

Curve.from_asn1 = from_asn1;
Curve.ks_parse = ks_parse;
module.exports.Curve = Curve;
module.exports.Field = Field;
module.exports.pkey = pkey;
module.exports.pubkey = pubkey;
module.exports.std_curve = std_curve;
