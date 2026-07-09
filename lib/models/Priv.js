/*jslint plusplus: true */
/*
 * Priv - DSTU 4145 private key model.
 *
 * Wraps a private scalar `d` over a binary-field EC curve and provides the
 * operations built on it: DSTU 4145 signing, ECDH-style key agreement
 * (Diffie-Hellman derive + GOST 28147 KDF for CMS enveloped data), public key
 * recovery, and (de)serialization to/from the Ukrainian key container formats
 * (DstuPrivkey ASN.1, PEM, PBES2, PFX and the proprietary Key-6.dat keystore).
 */
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

/**
 * Build the DER-encoded SharedInfo that seeds the GOST key-derivation salt.
 * @param {Buffer} [ukm] Optional user keying material (entityInfo).
 * @returns {Buffer} DER-encoded SharedInfo used as KDF salt.
 */
function gost_salt(ukm) {
  // suppPubInfo 0x00000100 encodes the KEK length in bits (256) per DSTU KDF.
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

/**
 * Detect the encoding of a raw private key input.
 * @param {*} inp Candidate private key material.
 * @returns {string} "hex" when the input is a hex string.
 */
function detect_format(inp) {
  if (util.is_hex(inp) === true) {
    return "hex";
  }
  throw new Error("Unknown privkey format");
}

/**
 * Parse the optional attribute block of a DstuPrivkey into a second key.
 * Ukrainian containers may carry a second (key-agreement) key inside attrs.
 * @param {Array} attr Decoded attribute list from the ASN.1 structure.
 * @returns {Object|undefined} Recovered Priv key, or undefined when absent.
 */
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

  // Attribute key bits are stored MSB-inverted; BIG_INVERT restores scalar d.
  return curve.pkey(util.BIG_INVERT(priv1_d), "buf8");
}

/**
 * Reconstruct a custom Curve from explicit DSTU 4145 domain parameters.
 * @param {Object} p Decoded ASN.1 curve parameters (field, a, b, order, bp).
 * @returns {Curve} Curve instance described by the parameters.
 */
function curve_params(p) {
  return new Curve({
    m: p.p.param_m,
    ks: Curve.ks_parse(p.p.ks),
    a: [p.param_a],
    b: util.BIG_LE(p.param_b),
    order: util.BIG_BE(p.order.toArray()),
    // Cofactor h: 4 when a=0, 2 when a=1 (DSTU curves have h in {2,4}).
    kofactor: [4 >> p.param_a],
    base: util.BIG_LE(p.bp)
  });
}

/**
 * Decode a DstuPrivkey ASN.1 blob into a Priv key (or a full key store).
 * @param {Buffer} data DER-encoded DstuPrivkey.
 * @param {boolean} [return_store] When true, return a {keys, format} store.
 * @returns {Object} A Priv key, or a store object listing all keys found.
 */
function from_asn1(data, return_store) {
  let key0, key1, priv, curve;

  priv = DstuPrivkey.decode(data, "der");
  const params = priv.priv0.p.p;
  // Curve is either referenced by named OID ("id") or fully inlined ("params").
  curve =
    params.type === "id" ? stdCurve(params.value) : curve_params(params.value);
  // param_d is little-endian; BIG_LE turns it into the scalar for pkey().
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

/**
 * Serialize an {s, r} signature into DSTU "short" wire form.
 * @param {Object} sign Signature with Field components s and r.
 * @param {boolean} [raw] When true, drop the 2-byte ASN.1-ish header (le form).
 * @returns {Buffer} Concatenated little-endian r||s, optionally with header.
 */
function short_sign(sign, raw) {
  const tmp_s = sign.s.truncate_buf8();
  const tmp_r = sign.r.truncate_buf8();
  // Both halves are padded to the wider of r/s so they occupy equal space.
  const mlen = Math.max(tmp_s.length, tmp_r.length);
  const sbuf = Buffer.alloc(2 + mlen * 2);
  // Header: 0x04 (OCTET STRING tag) followed by total payload length.
  sbuf.writeUInt8(4, 0);
  sbuf.writeUInt8(mlen * 2, 1);

  // r first, byte-reversed to little-endian (source buf8 is big-endian).
  for (let idx = 0; idx < mlen; idx++) {
    const tmp = tmp_r[mlen - idx - 1];
    sbuf.writeUInt8(tmp < 0 ? 256 + tmp : tmp, idx + 2);
  }

  // s second, likewise little-endian, placed right after r.
  for (let idx = 0; idx < mlen; idx++) {
    const tmp = tmp_s[mlen - idx - 1];
    sbuf.writeUInt8(tmp < 0 ? 256 + tmp : tmp, idx + 2 + mlen);
  }
  if (raw) {
    return sbuf.slice(2);
  }

  return sbuf;
}

/**
 * Serialize a signature into the requested wire format.
 * @param {Object} data Signature with Field components s and r.
 * @param {string} fmt Target format: "short" (with header) or "le" (raw).
 * @returns {Buffer} Serialized signature.
 */
function sign_serialise(data, fmt) {
  if (fmt === "short" || fmt === "le") {
    return short_sign(data, fmt === "le");
  }

  throw new Error("Unkown signature format " + fmt);
}

class Priv {
  /**
   * @param {Curve} p_curve DSTU 4145 curve the key lives on.
   * @param {Field|*} param_d Private scalar d (Field, or value to wrap).
   */
  constructor(p_curve, param_d) {
    this.type = "Priv";
    this.d = param_d._is_field ? param_d : new Field(param_d, "bn", p_curve);
    this.curve = p_curve;
    this.algorithm = "Dstu4145le";
  }

  /**
   * Core DSTU 4145 signing step for one random nonce e.
   * @param {Field} hash_v Message hash mapped into the field.
   * @param {Field} rand_e Per-signature random nonce e.
   * @returns {Object|null} {s, r} signature, or null to retry with new e.
   */
  help_sign(hash_v, rand_e) {
    // eG = e*G; the x-coordinate of this point is the presignature.
    const eG = this.curve.base.mul(rand_e);
    if (eG.x.is_zero()) {
      return null;
    }
    // r = FE-to-int( hash * eG.x ) in the field, then truncated to order bits.
    let r = hash_v.mod_mul(eG.x);

    r = this.curve.truncate(r);
    if (r.is_zero()) {
      return null;
    }

    // s = (e + d*r) mod n, computed with big integers modulo the group order.
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

  /**
   * Sign a message hash, retrying nonces until a valid signature is produced.
   * @param {Buffer} hash_buf Message hash bytes.
   * @param {string} [fmt] Optional serialization format ("short"/"le").
   * @returns {Object|Buffer} {s, r, hash} object, or serialized signature.
   */
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

    // Loop: a fresh nonce e is drawn until help_sign yields non-degenerate r/s.
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

  /**
   * Decrypt CMS enveloped data addressed to this key.
   * @param {Buffer} data Ciphertext.
   * @param {Object} pubkey Sender public key (or object carrying .pubkey).
   * @param {Object} param Envelope params: ukm, wcek (wrapped CEK), iv.
   * @param {Object} algo Algorithm bundle (kdf, keyunwrap, decrypt).
   * @returns {Buffer} Recovered plaintext.
   */
  decrypt(data, pubkey, param, algo) {
    if (pubkey.pubkey) {
      pubkey = pubkey.pubkey;
    }
    // Derive the key-encryption key via ECDH, unwrap the CEK, then decrypt.
    const kek = this.sharedKey(pubkey, param.ukm, algo.kdf);
    const cek = algo.keyunwrap(kek, param.wcek);
    return algo.decrypt(data, cek, param.iv);
  }

  /**
   * Encrypt data for a recipient certificate using CMS-style key wrapping.
   * @param {Buffer} data Plaintext.
   * @param {Object} cert Recipient certificate (provides .pubkey).
   * @param {Object} algo Algorithm bundle (kdf, keywrap, encrypt).
   * @returns {Object} {iv, wcek, data, ukm} envelope material.
   */
  encrypt(data, cert, algo) {
    // Random content-encryption key, user keying material and IV per message.
    const cek = random(Buffer.alloc(32));
    const ukm = random(Buffer.alloc(64));
    const iv = random(Buffer.alloc(8));

    // KEK from ECDH with recipient pubkey; CEK is wrapped under it.
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

  /**
   * Test whether a given public key corresponds to this private key.
   * @param {Object|Field|Buffer} pub_key Pub instance, Field, or raw bytes.
   * @returns {boolean} True when the public key matches this private key.
   */
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

  /**
   * Compressed form of this key's public point (memoized).
   * @returns {Field} Compressed public key.
   */
  pub_compress() {
    if (this._pub === undefined) {
      this._pub = this.pub();
    }

    if (this._pub_cmp === undefined) {
      this._pub_cmp = this._pub.point.compress();
    }

    return this._pub_cmp;
  }

  /**
   * Compute the public key Q from the private scalar.
   * @returns {Pub} Public key. Q = -(d*G): DSTU uses the negated base multiple.
   */
  pub() {
    return new Pub(this.curve, this.curve.base.mul(this.d).negate());
  }

  /**
   * ECDH shared secret: derive the raw ZZ bytes from a peer public key.
   * @param {Object|*} pubkey Peer Pub instance or point-convertible value.
   * @returns {Buffer} ZZ = x-coordinate of d*h*Q, trimmed to field byte size.
   */
  derive(pubkey) {
    let pointQ, pointZ, bufZZ, cut;
    if (pubkey.type === "Pub") {
      pointQ = pubkey.point;
    } else {
      pointQ = this.curve.point(pubkey);
    }
    // Z = (d*h)*Q; multiplying by the cofactor h yields the shared point.
    pointZ = pointQ.mul(this.d.mod_mul(this.curve.kofactor));
    bufZZ = Buffer.from(pointZ.x.buf8(), "binary");
    // Keep only the low ceil(m/8) bytes of the x-coordinate.
    cut = bufZZ.length - Math.ceil(this.curve.m / 8);
    return bufZZ.slice(cut);
  }

  /**
   * Derive a key-encryption key (KEK) from an ECDH secret via the GOST KDF.
   * @param {Object|*} pubkey Peer public key.
   * @param {Buffer} ukm User keying material mixed into the salt.
   * @param {Function} kdf GOST 34.311 based key-derivation function.
   * @returns {Buffer} Derived KEK.
   */
  sharedKey(pubkey, ukm, kdf) {
    let zz = this.derive(pubkey);
    // Drop a leading zero byte so ZZ length matches the reference KDF input.
    if (zz[0] === 0) {
      zz = zz.slice(1);
    }
    // KDF input is ZZ || counter(=1) || SharedInfo salt, hashed by kdf().
    const counter = Buffer.from("\x00\x00\x00\x01", "binary");
    const salt = gost_salt(ukm);

    const kek_input = Buffer.alloc(zz.length + counter.length + salt.length);
    zz.copy(kek_input);
    counter.copy(kek_input, zz.length);
    salt.copy(kek_input, zz.length + counter.length);

    return kdf(kek_input);
  }

  /**
   * Serialize this key as a PEM-wrapped DstuPrivkey.
   * @returns {string} PEM text.
   */
  as_pem() {
    return (
      "-----BEGIN PRIVATE KEY-----\n" +
      b64_encode(this.as_asn1(), { line: 16, pad: true }) +
      "\n-----END PRIVATE KEY-----"
    );
  }

  /**
   * Alias for as_pem().
   * @returns {string} PEM text.
   */
  to_pem() {
    return this.as_pem();
  }

  /**
   * Serialize this key as a DER-encoded DstuPrivkey.
   * @returns {Buffer} DER bytes.
   */
  as_asn1() {
    const key = this.as_struct();
    return DstuPrivkey.encode(key, "der");
  }

  /**
   * Alias for as_asn1().
   * @returns {Buffer} DER bytes.
   */
  to_asn1() {
    return this.as_asn1();
  }

  /**
   * Build the plain JS object matching the DstuPrivkey ASN.1 schema.
   * @returns {Object} Structure ready for DstuPrivkey.encode.
   */
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
      // param_d is stored little-endian, so reverse the big-endian buf8 bytes.
      param_d: Array.prototype.slice.call(this.d.buf8()).reverse(),
      attr: []
    };
    return key;
  }

  /**
   * Serialize this key into a password-protected PBES2 container.
   * @param {string|Buffer} password Encryption password.
   * @param {Object} algo Algorithm bundle providing storesave().
   * @returns {Buffer} PBES2 serialized container.
   */
  to_pbes2(password, algo) {
    const iv = random(Buffer.alloc(8));
    const salt = random(Buffer.alloc(32));
    return pbes2.enc_serialize(
      algo.storesave(Buffer.from(this.to_asn1()), "PBES2", password, iv, salt)
    );
  }

  /**
   * Decode a DstuPrivkey from DER bytes.
   * @param {Buffer} data DER-encoded key.
   * @param {boolean} [return_store] Return a key store instead of a single key.
   * @returns {Object} Priv key or key store.
   */
  static from_asn1(data, return_store) {
    return from_asn1(data, return_store);
  }

  /**
   * Decode a DstuPrivkey from PEM (or raw DER) input.
   * @param {string|Buffer} data PEM text or DER bytes.
   * @param {boolean} [return_store] Return a key store instead of a single key.
   * @returns {Object} Priv key or key store.
   */
  static from_pem(data, return_store) {
    return from_asn1(pem.maybe_pem(data), return_store);
  }

  /**
   * Detect the encoding of raw private key input.
   * @param {*} inp Candidate key material.
   * @returns {string} Detected format.
   */
  static detect_format(inp) {
    return detect_format(inp);
  }

  /**
   * Load keys/certs from a (possibly password-protected) container of any
   * supported format (PBES2, PFX, or the proprietary Key-6.dat keystore).
   * @param {string|Buffer} data Container bytes (PEM or DER).
   * @param {string|Buffer} [password] Password; omit for unprotected input.
   * @param {Object} [algo] Algorithm bundle providing storeload().
   * @returns {Object} Merged {certs, keys, format} store.
   */
  static from_protected(data, password, algo) {
    let stores;
    if (password && (!algo || !algo.storeload)) {
      throw new Error("Cant decode protected file without algo");
    }

    data = pem.maybe_pem(data);
    if (password) {
      // Try each container format; keep the first that parses. A parser that
      // returns nothing (instead of throwing) must not clobber an earlier hit.
      try {
        stores = pbes2.pbes2_parse(data) || stores;
      } catch (ignore) {}
      try {
        stores = pfx.pfx_parse(data) || stores;
      } catch (ignore) {}
      try {
        const ks = keystore.enc_parse(data);
        if (ks) {
          stores = [ks];
        }
      } catch (ignore) {}

      if (!stores) {
        throw new Error(
          "Cant parse store with either PBES2 or proprietaty format"
        );
      }

      // Decrypt each parsed store part with the password to plain ASN.1.
      data = stores.map(part => algo.storeload(part, password));
    } else {
      data = [data];
    }
    return merge_stores(data.map(guessStore));
  }

  /**
   * Static wrapper for signature serialization.
   * @param {Object} data Signature {s, r}.
   * @param {string} fmt Target format.
   * @returns {Buffer} Serialized signature.
   */
  static sign_serialise(data, fmt) {
    return sign_serialise(data, fmt);
  }
}

/**
 * Merge decoded store fragments, splitting keys and certificates apart.
 * @param {Array<Object>} list Per-fragment {format, keys|certs} results.
 * @returns {Object} Combined {certs, keys, format:"privkeys"} store.
 */
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

/**
 * Interpret one decoded blob as either a private-key store or a cert bag.
 * @param {Buffer} data Decoded ASN.1 bytes.
 * @returns {Object} A keys store, or a {format:"certbags", certs} store.
 */
function guessStore(data) {
  // Try to read it as a private key first; fall back to a certificate bag.
  try {
    return Priv.from_asn1(data, true);
  } catch (e) {}

  return { format: "certbags", certs: pfx.certbags_from_asn1(data) };
}

export default Priv;
