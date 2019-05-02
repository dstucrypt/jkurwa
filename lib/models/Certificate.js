/* eslint-disable camelcase */
/* eslint-disable no-underscore-dangle */
/* eslint-disable no-bitwise */
const asn1 = require("asn1.js");
const jk = require("../curve.js");

const rfc3280 = require("../spec/rfc3280.js");

const util = require("../util.js");
const pem = require("../util/pem");
const { b64_encode } = require("../util/base64.js");

const OID = {
  "1 2 804 2 1 1 1 11 1 4 1 1": "DRFO",
  "1 2 804 2 1 1 1 11 1 4 2 1": "EDRPOU"
};

const OID_LINK = {
  "1 3 6 1 5 5 7 48 1": "ocsp",
  "1 3 6 1 5 5 7 48 2": "issuers",
  "1 3 6 1 5 5 7 48 3": "tsp"
};

const IPN_VAL = asn1.define("IPN_VAL", function body_IPN_VAL() {
  this.implicit(0x13).octstr();
});

const IPN_ID = asn1.define("IPN_ID", function body_IPN_ID() {
  this.seq().obj(this.key("id").objid(OID), this.key("val").setof(IPN_VAL));
});

const IPN = asn1.define("IPN", function body_IPN() {
  this.seqof(IPN_ID);
});

const Link = asn1.define("Link", function body_LINK() {
  this.seq().obj(
    this.key("id").objid(OID_LINK),
    this.key("link")
      .implicit(6)
      .ia5str()
  );
});

const AIA = asn1.define("AIA", function body_AIA() {
  this.seqof(Link);
});

function str(buf) {
  let off = 2;
  if (buf[1] & 0x80) {
    off += buf[1] ^ 0x80;
  }
  if (buf[0] === 0xc) {
    return buf.slice(off).toString("utf8");
  }
  return buf.slice(off).toString("binary");
}

function formatRDN(serial, rdnlist) {
  const ret = serial.toString(16);

  const part = [];
  rdnlist.forEach(elements => {
    elements.forEach(el => {
      part.push(`${el.type}=${str(el.value)}`);
    });
  });

  return `${ret}@${part.join("/")}`;
}

function parse_aia(data, upd) {
  const asn_aia = AIA.decode(data, "der");
  return asn_aia.reduce((acc, item) => {
    acc[item.id] = item.link;
    return acc;
  }, upd || {});
}

function parse_ipn(data) {
  const ret = {};
  const asn_ib = IPN.decode(data, "der");
  for (let i = 0; i < asn_ib.length; i += 1) {
    const part = asn_ib[i];
    ret[part.id] = String.fromCharCode.apply(null, part.val[0]);
  }
  return ret;
}

function parse_ext(asn_ob) {
  const ret = {};
  for (let i = 0; i < asn_ob.length; i += 1) {
    const part = asn_ob[i];
    ret[part.extnID] = part.extnValue;
  }
  if (ret.subjectDirectoryAttributes !== undefined) {
    ret.ipn = parse_ipn(ret.subjectDirectoryAttributes);
  }
  if (ret.authorityInfoAccess !== undefined) {
    parse_aia(ret.authorityInfoAccess, ret);
  }
  if (ret.subjectInfoAccess !== undefined) {
    parse_aia(ret.subjectInfoAccess, ret);
  }
  return ret;
}

function parse_dn(asn_ob) {
  const ret = {};
  for (let i = 0; i < asn_ob.length; i += 1) {
    for (let j = 0; j < asn_ob[i].length; j += 1) {
      const part = asn_ob[i][j];
      ret[part.type] = str(part.value);
    }
  }
  return ret;
}

class Certificate {
  static from_asn1(data) {
    const cert = rfc3280.Certificate.decode(data, "der");
    cert._raw = data;
    return new Certificate(cert);
  }

  static from_pem(data) {
    return Certificate.from_asn1(pem.maybe_pem(data));
  }

  constructor(cert, lazy) {
    this.setup(cert, lazy);
    this._raw = cert._raw;
    delete cert._raw; // eslint-disable-line no-param-reassign
  }

  setup(cert, lazy) {
    const tbs = cert.tbsCertificate;

    const pk = tbs.subjectPublicKeyInfo;

    const pk_data = pk.subjectPublicKey.data.slice(2);

    this.format = "x509";
    this.curve =
      pk.algorithm.algorithm === "Dstu4145le"
        ? jk.Curve.resolve(pk.algorithm.parameters.curve, "cert")
        : null;
    this.curve_id =
      pk.algorithm.algorithm === "ECDSA" ? pk.algorithm.parameters.value : null;
    this.pk_data = util.BIG_LE(pk_data);
    this.valid = {
      from: tbs.validity.notBefore.value,
      to: tbs.validity.notAfter.value
    };
    this.serial = cert.tbsCertificate.serialNumber;
    this.signatureAlgorithm = cert.signatureAlgorithm.algorithm;
    this.pubkeyAlgorithm =
      cert.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm;
    this.extension = parse_ext(cert.tbsCertificate.extensions);
    this.issuer = parse_dn(cert.tbsCertificate.issuer.value);
    this.subject = parse_dn(cert.tbsCertificate.subject.value);
    this.ob = cert;
    if (!lazy && this.curve) {
      this.pubkey_unpack();
    }
  }

  pubkey_unpack() {
    if (!this.pubkey) this.pubkey = this.curve.pubkey(this.pk_data);
  }

  as_asn1() {
    if (this._raw !== undefined) {
      return this._raw;
    }

    return rfc3280.Certificate.encode(this.ob, "der");
  }

  to_asn1() {
    return this.as_asn1();
  }

  as_pem() {
    return `-----BEGIN CERTIFICATE-----\n${b64_encode(this.to_asn1(), {
      line: 16,
      pad: true
    })}\n-----END CERTIFICATE-----`;
  }

  to_pem() {
    return this.as_pem();
  }

  as_dict() {
    const x = this;
    return {
      subject: x.subject,
      issuer: x.issuer,
      extension: x.extension,
      valid: x.valid
    };
  }

  nameSerial() {
    return {
      issuer: this.ob.tbsCertificate.issuer,
      serialNumber: this.ob.tbsCertificate.serialNumber
    };
  }

  rdnSerial() {
    return formatRDN(
      this.ob.tbsCertificate.serialNumber,
      this.ob.tbsCertificate.issuer.value
    );
  }

  name_asn1() {
    return rfc3280.Name.encode(this.ob.tbsCertificate.issuer, "der");
  }
}

module.exports = Certificate;
module.exports.formatRDN = formatRDN;
