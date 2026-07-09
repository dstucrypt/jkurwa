/*
 * DSTU key store / private-key ASN.1 spec.
 *
 * Models for the IIT "Store" container and the DSTU 4145 private-key structure,
 * including the elliptic-curve parameters (named curves and explicit binary-
 * field polynomial parameters) and the key attribute bags. Registers the DSTU
 * public-key algorithms with rfc3280 on import so certificates can decode them.
 */
import asn1 from "asn1.js";
import * as rfc3280 from "./rfc3280.js";

var OID = {
  "1 2 804 2 1 1 1 1 3 1 1": "DSTU_4145_LE",
  "1 3 6 1 4 1 19398 1 1 2 3": "DSTU_4145_KEY_BITS",
  "1 3 6 1 4 1 19398 1 1 2 2": "DSTU_4145_CURVE"
};

var KeyAttrValue = asn1.define("KeyAttrValue", function () {
  this.choice({
    param_d: this.bitstr(),
    dstu4145: this.use(DstuParams),
    unknown: this.any()
  });
});

var KeyAttrValues = asn1.define("KeyAttrValues", function () {
  this.setof(KeyAttrValue);
});

var KeyAttr = asn1.define("Attr", function () {
  this.seq().obj(
    this.key("id").objid(OID),
    this.key("value").use(KeyAttrValues)
  );
});

// Middle-coefficient exponents (k1<k2<k3) of a pentanomial reduction poly.
var Pentanominal = asn1.define("Pentanominal", function () {
  this.seq().obj(
    this.key("k1").int(),
    this.key("k2").int(),
    this.key("k3").int()
  );
});

// Reduction polynomial of the binary field: either a trinomial (single middle
// exponent) or a pentanomial (three middle exponents).
var Polynomial = asn1.define("Polynomial", function () {
  this.choice({
    trinominal: this.int(),
    pentanominal: this.use(Pentanominal)
  });
});

// Explicit DSTU curve over GF(2^m): field degree m and reduction polynomial,
// curve coefficients a and b, group order and the base point.
var CurveParams = asn1.define("CurveParams", function () {
  this.seq().obj(
    this.key("p")
      .seq()
      .obj(this.key("param_m").int(), this.key("ks").use(Polynomial)),
    this.key("param_a").int(),
    // param_b is stored inverted (reverse byte order)
    this.key("param_b").octstr(), // inverted
    this.key("order").int(),
    this.key("bp").octstr()
  );
});

var CURVES = {
  "1 2 804 2 1 1 1 1 3 1 1 2 0": "DSTU_PB_163",
  "1 2 804 2 1 1 1 1 3 1 1 2 1": "DSTU_PB_167",
  "1 2 804 2 1 1 1 1 3 1 1 2 2": "DSTU_PB_173",
  "1 2 804 2 1 1 1 1 3 1 1 2 3": "DSTU_PB_179",
  "1 2 804 2 1 1 1 1 3 1 1 2 4": "DSTU_PB_191",
  "1 2 804 2 1 1 1 1 3 1 1 2 5": "DSTU_PB_233",
  "1 2 804 2 1 1 1 1 3 1 1 2 6": "DSTU_PB_257",
  "1 2 804 2 1 1 1 1 3 1 1 2 7": "DSTU_PB_307",
  "1 2 804 2 1 1 1 1 3 1 1 2 8": "DSTU_PB_367",
  "1 2 804 2 1 1 1 1 3 1 1 2 9": "DSTU_PB_431",
  "1 2 840 10045 3 1 7": "secp256r1"
};

// A curve is referenced either by a named-curve OID or by explicit parameters.
var Curve = asn1.define("Curve", function () {
  this.choice({
    id: this.objid(CURVES),
    params: this.use(CurveParams)
  });
});

// DSTU 4145 domain parameters: the curve plus optional S-box (dke) tables.
var DstuParams = asn1.define("CurveParams", function () {
  this.seq().obj(
    this.key("curve").use(Curve),
    this.key("dke").optional().octstr(),
    this.key("dke2").optional().octstr()
  );
});
export { DstuParams };
// Register DSTU/ECDSA public-key algorithms so rfc3280 can decode SPKIs.
rfc3280.injectPubAlgo("Dstu4145le", DstuParams);
rfc3280.injectPubAlgo("ECDSA", Curve);

// DSTU 4145 private key: version, algorithm+curve params, the private value
// (param_d, octet string) and optional key attributes.
var DstuPrivkey = asn1.define("DstuPrivkey", function () {
  this.seq().obj(
    this.key("version").int(),
    this.key("priv0")
      .seq()
      .obj(
        this.key("id").objid(OID),
        this.key("p")
          .seq()
          .obj(this.key("p").use(Curve), this.key("sbox").optional().octstr())
      ),
    this.key("param_d").octstr(),
    this.key("attr").optional().implicit(0).seqof(KeyAttr)
  );
});

export { DstuPrivkey };

// IIT proprietary key store: crypto type + params (a 4-byte MAC and optional
// padding) wrapping the encrypted key material in cryptData.
var StoreIIT = asn1.define("StoreIIT", function () {
  this.seq().obj(
    this.key("cryptParam")
      .seq()
      .obj(
        this.key("cryptType").objid({
          "1 3 6 1 4 1 19398 1 1 1 2": "IIT Store",
          "1 2 840 113549 1 5 13": "PBES2",
          "1 2 840 113549 1 5 12": "PBKDF2",
          "1 2 804 2 1 1 1 1 1 2": "GOST_34311_HMAC",
          "1 2 804 2 1 1 1 1 1 1 3": "GOST_28147_CFB",
          "1 2 804 2 1 1 1 1 3 1 1": "DSTU_4145_LE"
        }),
        this.key("cryptParam")
          .seq()
          .obj(this.key("mac").octstr(), this.key("pad").octstr().optional())
      ),
    this.key("cryptData").octstr()
  );
});

/**
 * Decode an IIT key store container and extract its MAC, padding and body.
 * @param {Buffer} data DER-encoded StoreIIT structure.
 * @returns {{format: string, mac: Buffer, pad: Buffer, body: Buffer}} MAC (4 bytes), padding and encrypted key body.
 * @throws {Error} If the MAC/pad lengths are invalid or the storage type is not "IIT Store".
 */
var enc_parse = function (data) {
  var asn1 = StoreIIT.decode(data, "der"),
    mac,
    pad;
  mac = asn1.cryptParam.cryptParam.mac;
  pad = asn1.cryptParam.cryptParam.pad;

  if (mac.length !== 4) {
    throw new Error("Invalid mac len " + mac.length);
  }
  if (pad.length >= 8) {
    throw new Error("Invalid pad len " + pad.length);
  }
  if (asn1.cryptParam.cryptType !== "IIT Store") {
    throw new Error("Invalid storage type");
  }

  return {
    format: "IIT",
    mac: mac,
    pad: pad,
    body: asn1.cryptData
  };
};

export { StoreIIT, enc_parse };
