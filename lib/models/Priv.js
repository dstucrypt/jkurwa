/*jslint plusplus: true */
import { Curve, std_curve as stdCurve } from "../curve.js";
import asn1 from "asn1.js";
import * as util from "../util.js";
import random from "../rand.js";
import * as pem from "../util/pem.js";
import { b64_encode } from "../util/base64.js";
import * as dstszi2010 from "../spec/dstszi2010.js";
import * as pbes2 from "../spec/pbes.js";
import * as pfx from "../spec/pfx.js";
import * as keystore from "../spec/keystore.js";
import { DstuPrivkey } from "../spec/keystore.js";
import Pub from "./Pub.js";
import { Field } from "../field.js";
import { Buffer } from "buffer";

const bn = asn1.bignum;

function gost_salt(ukm) {
  return dstszi2010.SharedInfo.encode(
    {
      keyInfo: {
        algorithm: "Gost28147-cfb-wrap",
        parameters: null
      },
      entityInfo: ukm || undefined,
      suppPubInfo: Buffer.from("\x00\x00\x01\x00", "binary")
    },
    "der"
  );
}

function detect_format(inp) {
  if (util.is_hex(inp) === true) {
    return "hex";
  }
  throw new Error("Unknown privkey format");
}

function attr_parse(attr) {
  const ahash = {};
  let aob, priv1_d, dstu, curve;
  for (let i = 0; i < attr.length; i++) {
    aob = attr[i];
    if (aob.id !== undefined) {
      ahash[aob.id] = aob.value[0].value;
    }
  }
  if (!ahash.DSTU_4145_KEY_BITS) {
    return undefined;
  }

  if (ahash.DSTU_4145_CURVE === undefined) {
    return undefined;
  }

  priv1_d = ahash.DSTU_4145_KEY_BITS.data;
  dstu = ahash.DSTU_4145_CURVE;
  if (priv1_d === undefined || priv1_d.length === 0) {
    return undefined;
  }

  curve = Curve.resolve(dstu.curve);

  return curve.pkey(util.BIG_INVERT(priv1_d), "buf8");
}

function curve_params(p) {
  return new Curve({
    m: p.p.param_m,
    ks: Curve.ks_parse(p.p.ks),
    a: [p.param_a],
    b: util.BIG_LE(p.param_b),
    order: util.BIG_BE(p.order.toArray()),
    kofactor: [4 >> p.param_a],
    base: util.BIG_LE(p.bp)
  });
}

function from_asn1(data, return_store) {
  let key0, key1, priv, curve;

  priv = DstuPrivkey.decode(data, "der");
  const params = priv.priv0.p.p;
  curve =
    params.type === "id"
      ? jk.std_curve(params.value)
      : curve_params(params.value);
  key0 = curve.pkey(util.BIG_LE(priv.param_d), "buf32");
  key0.sbox = priv.priv0.p.sbox;
  if (return_store !== true) {
    return key0;
  }

  key1 = priv.attr && attr_parse(priv.attr);
  return {
    keys: key1 ? [key0, key1] : [key0],
    format: "privkeys"
  };
}

function short_sign(sign, raw) {
  const tmp_s = sign.s.truncate_buf8();
  const tmp_r = sign.r.truncate_buf8();
  const mlen = Math.max(tmp_s.length, tmp_r.length);
  const sbuf = Buffer.alloc(2 + mlen * 2);
  sbuf.writeUInt8(4, 0);
  sbuf.writeUInt8(mlen * 2, 1);

  for (let idx = 0; idx < mlen; idx++) {
    const tmp = tmp_r[mlen - idx - 1];
    sbuf.writeUInt8(tmp < 0 ? 256 + tmp : tmp, idx + 2);
  }

  for (let idx = 0; idx < mlen; idx++) {
    const tmp = tmp_s[mlen - idx - 1];
    sbuf.writeUInt8(tmp < 0 ? 256 + tmp : tmp, idx + 2 + mlen);
  }
  if (raw) {
    return sbuf.slice(2);
  }

  return sbuf;
}

function sign_serialise(data, fmt) {
  if (fmt === "short" || fmt === "le") {
    return short_sign(data, fmt === "le");
  }

  throw new Error("Unkown signature format " + fmt);
}

class Priv {
  constructor(p_curve, param_d) {
    this.type = "Priv";
    this.d = param_d._is_field ? param_d : new Field(param_d, "bn", p_curve);
    this.curve = p_curve;
    this.algorithm = "Dstu4145le";
  }

  help_sign(hash_v, rand_e) {
    const eG = this.curve.base.mul(rand_e);
    if (eG.x.is_zero()) {
      return null;
    }
    let r = hash_v.mod_mul(eG.x);

    r = this.curve.truncate(r);
    if (r.is_zero()) {
      return null;
    }

    r = new bn.BN(r.buf8(), 8);
    const big_d = new bn.BN(this.d.buf8(), 8);
    const big_rand_e = new bn.BN(rand_e.buf8(), 8);
    const big_order = new bn.BN(this.curve.order.buf8(), 8);
    let s = big_d.mul(r).mod(big_order);
    s = s.add(big_rand_e).mod(big_order);

    return {
      s: new Field(s.toArray(), "buf8", this.curve),
      r: new Field(r.toArray(), "buf8", this.curve)
    };
  }

  sign(hash_buf, fmt) {
    let rand_e, ret, hash_v;

    if (Buffer.isBuffer(hash_buf)) {
      hash_v = new Field(util.add_zero(hash_buf, true), "buf8", this.curve);
    } else {
      throw new Error("not a buffer");
    }

    if (hash_v.is_zero()) {
      throw new Error("Pass non zero value");
    }

    while (true) {
      rand_e = this.curve.rand();

      ret = this.help_sign(hash_v, rand_e);
      if (ret !== null) {
        break;
      }
    }

    ret.hash = hash_v;
    if (fmt === undefined) {
      return ret;
    }
    return sign_serialise(ret, fmt);
  }

  decrypt(data, pubkey, param, algo) {
    if (pubkey.pubkey) {
      pubkey = pubkey.pubkey;
    }
    const kek = this.sharedKey(pubkey, param.ukm, algo.kdf);
    const cek = algo.keyunwrap(kek, param.wcek);
    return algo.decrypt(data, cek, param.iv);
  }

  encrypt(data, cert, algo) {
    const crypto = global.crypto;

    const cek = random(Buffer.alloc(32));
    const ukm = random(Buffer.alloc(64));
    const iv = random(Buffer.alloc(8));

    const kek = this.sharedKey(cert.pubkey, ukm, algo.kdf);
    const wcek = algo.keywrap(kek, cek, iv);
    const ctext = algo.encrypt(data, cek, iv);
    return {
      iv: iv,
      wcek: wcek,
      data: ctext,
      ukm: ukm
    };
  }

  pub_match(pub_key) {
    let check_key = null;
    if (pub_key.type === "Pub") {
      return pub_key.point.equals(this.pub().point);
    }
    if (pub_key._is_field) {
      check_key = pub_key;
    }
    if (Buffer.isBuffer(pub_key)) {
      check_key = new Field(pub_key, "buf8", this.curve);
    }
    if (check_key === null) {
      throw new Error("Unknow pubkey format");
    }

    return check_key.equals(this.pub_compress());
  }

  pub_compress() {
    if (this._pub === undefined) {
      this._pub = this.pub();
    }

    if (this._pub_cmp === undefined) {
      this._pub_cmp = this._pub.point.compress();
    }

    return this._pub_cmp;
  }

  pub() {
    return new Pub(this.curve, this.curve.base.mul(this.d).negate());
  }

  derive(pubkey) {
    let pointQ, pointZ, bufZZ, cut;
    if (pubkey.type === "Pub") {
      pointQ = pubkey.point;
    } else {
      pointQ = this.curve.point(pubkey);
    }
    pointZ = pointQ.mul(this.d.mod_mul(this.curve.kofactor));
    bufZZ = Buffer.from(pointZ.x.buf8(), "binary");
    cut = bufZZ.length - Math.ceil(this.curve.m / 8);
    return bufZZ.slice(cut);
  }

  sharedKey(pubkey, ukm, kdf) {
    let zz = this.derive(pubkey);
    if (zz[0] === 0) {
      zz = zz.slice(1);
    }
    const counter = Buffer.from("\x00\x00\x00\x01", "binary");
    const salt = gost_salt(ukm);

    const kek_input = Buffer.alloc(zz.length + counter.length + salt.length);
    zz.copy(kek_input);
    counter.copy(kek_input, zz.length);
    salt.copy(kek_input, zz.length + counter.length);

    return kdf(kek_input);
  }

  as_pem() {
    return (
      "-----BEGIN PRIVATE KEY-----\n" +
      b64_encode(this.as_asn1(), { line: 16, pad: true }) +
      "\n-----END PRIVATE KEY-----"
    );
  }

  to_pem() {
    return this.as_pem();
  }

  as_asn1() {
    const key = this.as_struct();
    return DstuPrivkey.encode(key, "der");
  }

  to_asn1() {
    return this.as_asn1();
  }

  as_struct() {
    const key = {
      version: 0,
      priv0: {
        id: "DSTU_4145_LE",
        p: {
          p: {
            type: "params",
            value: this.curve.as_struct()
          },
          sbox: dstszi2010.DEFAULT_SBOX_COMPRESSED
        }
      },
      param_d: Array.prototype.slice.call(this.d.buf8()).reverse(),
      attr: []
    };
    return key;
  }

  to_pbes2(password, algo) {
    const iv = random(Buffer.alloc(8));
    const salt = random(Buffer.alloc(32));
    return pbes2.enc_serialize(
      algo.storesave(Buffer.from(this.to_asn1()), "PBES2", password, iv, salt)
    );
  }

  static from_asn1(data, return_store) {
    return from_asn1(data, return_store);
  }

  static from_pem(data, return_store) {
    return from_asn1(pem.maybe_pem(data), return_store);
  }

  static detect_format(inp) {
    return detect_format(inp);
  }

  static from_protected(data, password, algo) {
    let stores;
    if (password && (!algo || !algo.storeload)) {
      throw new Error("Cant decode protected file without algo");
    }

    data = pem.maybe_pem(data);
    if (password) {
      try {
        stores = pbes2.pbes2_parse(data);
      } catch (ignore) {}
      try {
        stores = pfx.pfx_parse(data);
      } catch (ignore) {}
      try {
        stores = [keystore.enc_parse(data)];
      } catch (ignore) {}

      if (!stores) {
        throw new Error(
          "Cant parse store with either PBES2 or proprietaty format"
        );
      }

      data = stores.map(part => algo.storeload(part, password));
    } else {
      data = [data];
    }
    return merge_stores(data.map(guessStore));
  }

  static sign_serialise(data, fmt) {
    return sign_serialise(data, fmt);
  }
}

function merge_stores(list) {
  const ret = { certs: [], keys: [], format: "privkeys" };
  for (const store of list) {
    if (store.format === "privkeys") {
      ret.keys = ret.keys.concat(store.keys);
    }
    if (store.format === "certbags") {
      ret.certs = ret.certs.concat(store.certs);
    }
  }
  return ret;
}

function guessStore(data) {
  try {
    return Priv.from_asn1(data, true);
  } catch (e) {}

  return { format: "certbags", certs: pfx.certbags_from_asn1(data) };
}

export default Priv;
