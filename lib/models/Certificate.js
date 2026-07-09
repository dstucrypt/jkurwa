/*
 * X.509 certificate model for the DSTU 4145 (Ukrainian national standard) PKI.
 *
 * Wraps an RFC 3280 certificate structure and exposes helpers to:
 *   - decode/encode certificates (DER and PEM);
 *   - build and sign a new certificate (TBS construction with DSTU EC keys);
 *   - parse DSTU-specific extensions (taxpayer IPN/DRFO/EDRPOU, AIA links,
 *     key identifiers);
 *   - verify a certificate against its issuer, its validity window, its key
 *     usage and its DSTU 4145 signature, and walk the issuer chain.
 */
import asn1 from "asn1.js";
import { Curve } from "../curve.js";

import * as rfc3280 from "../spec/rfc3280.js";

import * as util from "../util.js";
import * as strutil from "../util/str.js";
import * as pem from "../util/pem.js";
import { b64_encode } from "../util/base64.js";

// Ukrainian taxpayer-identifier OIDs carried in the subjectDirectoryAttributes
// extension: DRFO (personal tax number) and EDRPOU (legal-entity registry code).
const OID = {
  "1 2 804 2 1 1 1 11 1 4 1 1": "DRFO",
  "1 2 804 2 1 1 1 11 1 4 7 1": "DRFO",
  "1 2 804 2 1 1 1 11 1 4 2 1": "EDRPOU"
};

// Access-method OIDs used inside authorityInfoAccess / subjectInfoAccess to
// label service URLs (OCSP responder, issuer CA cert, timestamp server).
const OID_LINK = {
  "1 3 6 1 5 5 7 48 1": "ocsp",
  "1 3 6 1 5 5 7 48 2": "issuers",
  "1 3 6 1 5 5 7 48 3": "tsp"
};

// ASN.1 schema for the Ukrainian taxpayer-identifier (IPN) attribute carried in
// the subjectDirectoryAttributes extension: a SEQUENCE OF { OID, SET OF value }.
const IPN_VAL = asn1.define("IPN_VAL", function body_IPN_VAL() {
  this.implicit(0x13).octstr();
});

const IPN_ID = asn1.define("IPN_ID", function body_IPN_ID() {
  this.seq().obj(this.key("id").objid(OID), this.key("val").setof(IPN_VAL));
});

const IPN = asn1.define("IPN", function body_IPN() {
  this.seqof(IPN_ID);
});

const UsageBits = asn1.define("USage", function body_Usage() {
  this.bitstr();
});

// AccessDescription: an access-method OID paired with a URL (context tag [6],
// uniformResourceIdentifier) — one entry of an Info-Access extension.
const Link = asn1.define("Link", function body_LINK() {
  this.seq().obj(
    this.key("id").objid(OID_LINK),
    this.key("link").implicit(6).ia5str()
  );
});

const AIA = asn1.define("AIA", function body_AIA() {
  this.seqof(Link);
});

// Key identifier: either a bare OCTET STRING (subjectKeyIdentifier) or a
// SEQUENCE wrapping the id in context tag [0] (authorityKeyIdentifier).
const KeyId = asn1.define("KeyId", function body_KeyId() {
  this.choice({
    str: this.octstr(),
    seq: this.seq().obj(this.key("str").implicit(0).octstr())
  });
});

const CertificateList = asn1.define("CertificateValues", function () {
  this.seqof(rfc3280.Certificate);
});

/**
 * Decode the raw bytes of a DirectoryString ASN.1 value into a JS string.
 * Skips the TLV tag + length prefix by hand (length may be long-form when the
 * high bit of the length byte is set) and picks UTF-8 only for the UTF8String
 * tag (0x0c), otherwise treats the payload as raw bytes.
 * @param {Buffer} buf raw DER-encoded string value (tag+length+content)
 * @returns {string} decoded text
 */
function reprstr(buf) {
  let off = 2;
  if (buf[1] & 0x80) {
    // Long-form length: low 7 bits give the number of length octets to skip.
    off += buf[1] ^ 0x80;
  }
  if (buf[0] === 0xc) {
    return buf.slice(off).toString("utf8");
  }
  return buf.slice(off).toString("binary");
}

/**
 * Wrap a value in a DER OCTET STRING. Used to build extnValue payloads.
 * @param {Buffer} input bytes to wrap
 * @returns {Buffer} DER-encoded OCTET STRING
 */
function str(input) {
  const STR = asn1.define("STR", function STR() {
    this.octstr();
  });
  return STR.encode(input, "der");
}

/**
 * Parse an Authority/Subject Information Access extension into an
 * { accessMethod: url } map keyed by the friendly OID_LINK name.
 * @param {Buffer} data DER-encoded AIA sequence
 * @returns {{id: string, link: string}} accumulated access entry
 */
function parse_aia(data) {
  const asn_aia = AIA.decode(data, "der");
  return asn_aia.reduce((acc, item) => {
    acc[item.id] = item.link;
    return acc;
  });
}

/**
 * Parse the subjectDirectoryAttributes extension into a map of Ukrainian
 * taxpayer identifiers, e.g. { DRFO: "...", EDRPOU: "..." }.
 * @param {Buffer} data DER-encoded IPN sequence
 * @returns {Object<string,string>} identifier name to value
 */
function parse_ipn(data) {
  const ret = {};
  const asn_ib = IPN.decode(data, "der");
  for (let i = 0; i < asn_ib.length; i += 1) {
    const part = asn_ib[i];
    // val is a SET OF octet strings; take the first and rebuild the string.
    ret[part.id] = String.fromCharCode.apply(null, part.val[0]);
  }
  return ret;
}

/**
 * Lift a parser so it tolerates absent (undefined/null) extension data.
 * @param {function(Buffer):*} fn parser to guard
 * @returns {function(Buffer):*} parser returning null when given no data
 */
function optional(fn) {
  return function (data) {
    return data ? fn(data) : null;
  };
}

/**
 * Flatten the certificate extension list into a keyed object, decoding the
 * DSTU-specific extensions (IPN, AIA/SIA, key identifiers) eagerly and leaving
 * keyUsage/extendedKeyUsage/basicConstraints as raw DER for lazy decoding.
 * @param {Array<{extnID: string, extnValue: Buffer}>} asn_ob decoded extensions
 * @returns {Object} parsed extension map
 */
function parse_ext(asn_ob) {
  const ext = {};
  for (let part of asn_ob) {
    ext[part.extnID] = part.extnValue;
  }
  return {
    keyUsage: ext.keyUsage,
    extendedKeyUsage: ext.extendedKeyUsage,
    basicConstraints: ext.basicConstraints,
    ipn: optional(parse_ipn)(ext.subjectDirectoryAttributes),
    authorityInfoAccess: optional(parse_aia)(ext.authorityInfoAccess),
    subjectInfoAccess: optional(parse_aia)(ext.subjectInfoAccess),
    subjectKeyIdentifier: optional(parseKeyId)(ext.subjectKeyIdentifier),
    authorityKeyIdentifier: optional(parseKeyId)(ext.authorityKeyIdentifier)
  };
}

/**
 * Flatten an X.501 Name (RDNSequence: sequence of sets of AttributeTypeAndValue)
 * into a simple { attributeType: text } map.
 * @param {Array<Array<{type: string, value: Buffer}>>} asn_ob decoded RDN list
 * @returns {Object<string,string>} distinguished-name attributes
 */
function parse_dn(asn_ob) {
  const ret = {};
  for (let i = 0; i < asn_ob.length; i += 1) {
    for (let j = 0; j < asn_ob[i].length; j += 1) {
      const part = asn_ob[i][j];
      ret[part.type] = reprstr(part.value);
    }
  }
  return ret;
}

/**
 * Decode a subject/authority KeyIdentifier extension, accepting both the bare
 * OCTET STRING form and the SEQUENCE-wrapped (AuthorityKeyIdentifier) form.
 * @param {Buffer} buffer DER-encoded key identifier
 * @returns {Buffer} the raw key-identifier bytes
 */
function parseKeyId(buffer) {
  const ob = KeyId.decode(buffer, "der");
  return ob.type === "str" ? ob.value : ob.value.str;
}

/**
 * @param {Buffer} buffer bytes to render
 * @returns {string} hexadecimal representation
 */
function as_hex(buffer) {
  return buffer.toString("hex");
}

/**
 * Build the RDN structure expected by the RFC 3280 encoder from a flat
 * { type: value } map, UTF-8 encoding each attribute value.
 * @param {Object<string,string>} obj distinguished-name attributes
 * @returns {{type: string, value: Array}} encoder-ready RDN
 */
function makeRDN(obj) {
  return {
    type: "rdn",
    value: Object.entries(obj).map(([type, value]) => [
      { type, value: strutil.encodeUtf8Str(value, "der") }
    ])
  };
}

class Certificate {
  /**
   * Decode a DER certificate. Keeps the original bytes on `_raw` so re-encoding
   * returns the exact input (avoids re-serialization differences).
   * @param {Buffer} data DER-encoded certificate
   * @returns {Certificate}
   */
  static from_asn1(data) {
    const cert = rfc3280.Certificate.decode(data, "der");
    cert._raw = data;
    return new Certificate(cert);
  }

  /**
   * Decode a certificate from PEM (or DER if it is not PEM-armored).
   * @param {string|Buffer} data PEM text or DER bytes
   * @returns {Certificate}
   */
  static from_pem(data) {
    return Certificate.from_asn1(pem.maybe_pem(data));
  }

  /**
   * DER-encode a TBSCertificate structure (the signed portion).
   * @param {Object} obj TBSCertificate object
   * @returns {Buffer} DER bytes
   */
  static encodeTBS(obj) {
    return rfc3280.TBSCertificate.encode(obj, "der");
  }

  /**
   * Assemble a v3 TBSCertificate for a DSTU 4145 key, including the standard
   * DSTU extensions: subject/authority key identifiers (both set to this key's
   * id, matching self-issued CA usage) and a critical keyUsage.
   * @param {Object} params
   * @param {*} params.serial certificate serial number
   * @param {Object} params.pubkey DSTU public key (provides serialize()/keyid())
   * @param {string} params.algorithm public-key algorithm OID name
   * @param {Buffer} params.sbox DSTU DKE (S-box) parameter
   * @param {string} params.curve named curve identifier
   * @param {Object<string,string>} params.issuer issuer DN attributes
   * @param {Object<string,string>} params.subject subject DN attributes
   * @param {{from: Date, to: Date}} params.valid validity window
   * @param {string} params.usage keyUsage bits as a binary string
   * @param {function} params.hash hash function used to derive the key id
   * @returns {Object} TBSCertificate object
   */
  static createTBS({
    serial,
    pubkey,
    algorithm,
    sbox,
    curve,
    issuer,
    subject,
    valid,
    usage,
    hash
  }) {
    return {
      version: "v3",
      serialNumber: serial,
      issuer: makeRDN(issuer),
      subject: makeRDN(subject),
      subjectPublicKeyInfo: {
        subjectPublicKey: {
          data: pubkey.serialize()
        },
        algorithm: {
          algorithm,
          parameters: {
            curve: { type: "id", value: curve },
            dke: sbox
          }
        }
      },
      validity: {
        notBefore: { type: "utcTime", value: valid.from },
        notAfter: { type: "utcTime", value: valid.to }
      },
      extensions: [
        {
          extnID: "subjectKeyIdentifier",
          extnValue: str(pubkey.keyid({ hash }))
        },
        {
          extnID: "authorityKeyIdentifier",
          extnValue: str(pubkey.keyid({ hash }))
        },
        {
          extnID: "keyUsage",
          extnValue: Buffer.from(usage, "binary"),
          critical: true
        }
      ],
      signature: {
        algorithm
      }
    };
  }

  /**
   * Build and sign a certificate: derives the algorithm/curve/S-box from the
   * private key, encodes the TBS, hashes it and signs with DSTU 4145 in
   * little-endian ("le") form, wrapping the signature in an OCTET STRING.
   * @param {Object} params
   * @param {Object} params.privkey DSTU private key (sign/pub/curve/sbox)
   * @param {function} params.hash hash function applied to the encoded TBS
   * @param {Object} params.certData caller-supplied TBS fields (see createTBS)
   * @returns {Certificate} the signed certificate
   */
  static signCert({ privkey, hash, certData }) {
    const tbs = Certificate.createTBS(
      Object.assign(
        {},
        {
          algorithm: privkey.algorithm,
          curve: privkey.curve.name(),
          sbox: privkey.sbox,
          hash,
          pubkey: privkey.pub()
        },
        certData
      )
    );
    return new Certificate({
      tbsCertificate: tbs,
      signatureAlgorithm: {
        algorithm: privkey.algorithm
      },
      signature: {
        unused: 0,
        data: str(privkey.sign(hash(Certificate.encodeTBS(tbs)), "le"))
      }
    });
  }

  /**
   * Render a distinguished name as a stable "type=value/type=value" string,
   * used as a comparison key for issuer/subject matching.
   * @param {Array<Array<{type: string, value: Buffer}>>} rdnlist decoded RDN list
   * @returns {string} slash-joined DN
   */
  static formatDN(rdnlist) {
    const part = [];
    rdnlist.forEach(elements => {
      elements.forEach(el => {
        part.push(`${el.type}=${reprstr(el.value)}`);
      });
    });
    return part.join("/");
  }

  /**
   * Build a "serialHex@issuerDN" identifier for a certificate.
   * @param {Object} serial serial number (with toString(16))
   * @param {Array} rdnlist issuer RDN list
   * @returns {string} combined serial+DN key
   */
  static formatRDN(serial, rdnlist) {
    const ret = serial.toString(16);
    return `${ret}@${Certificate.formatDN(rdnlist)}`;
  }

  static List = {
    /**
     * Encode a list of certificates as a CAdES CertificateValues sequence.
     * @param {Array<Certificate>} list certificates to bundle
     * @returns {Buffer} DER-encoded sequence of Certificate
     */
    toCades(list) {
      return CertificateList.encode(
        list.map(iter => iter.ob),
        "der"
      );
    }
  };

  /**
   * @param {Object} cert decoded RFC 3280 certificate (optionally with `_raw`)
   * @param {boolean} [lazy] if true, defer public-key point unpacking
   */
  constructor(cert, lazy) {
    this.setup(cert, lazy);
    this._raw = cert._raw;
    delete cert._raw; // eslint-disable-line no-param-reassign
  }

  /**
   * Populate this instance from a decoded certificate: resolve the DSTU curve,
   * extract the public-key bytes, validity, serial, algorithms, extensions and
   * issuer/subject DNs.
   * @param {Object} cert decoded RFC 3280 certificate
   * @param {boolean} [lazy] skip public-key unpacking when true
   * @returns {void}
   */
  setup(cert, lazy) {
    const tbs = cert.tbsCertificate;

    const pk = tbs.subjectPublicKeyInfo;

    // Drop the 2-byte prefix: BIT STRING unused-bits octet plus the leading
    // OCTET STRING tag from the DSTU public-key wrapping.
    const pk_data = pk.subjectPublicKey.data.slice(2);

    this.format = "x509";
    // DSTU keys carry explicit curve parameters; ECDSA keys reference a curve
    // by OID only. Resolve one or the other, never both.
    this.curve =
      pk.algorithm.algorithm === "Dstu4145le"
        ? Curve.resolve(pk.algorithm.parameters.curve, "cert")
        : null;
    this.curve_id =
      pk.algorithm.algorithm === "ECDSA" ? pk.algorithm.parameters.value : null;
    // DSTU 4145 stores the public-key point as a little-endian big integer.
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

  /**
   * Full certificate validation against its issuer chain. Checks that:
   *   - the issuer can be found via the lookup function;
   *   - the issuer is itself valid (a trusted, self-signed root, or a CA
   *     recursively verified as of this cert's notBefore time);
   *   - the requested key usage is allowed;
   *   - the current time falls inside the validity window;
   *   - the DSTU signature verifies under the issuer's public key;
   *   - this cert's authorityKeyIdentifier matches the issuer's
   *     subjectKeyIdentifier, and its own subjectKeyIdentifier matches the
   *     hash of its public key (binding the key id to the actual key).
   * @param {{time: number, usage: string}} opts validation context
   * @param {Object<string,function>} hashes hash functions keyed by algorithm
   * @param {function(string, Buffer): Certificate} lookupFn issuer resolver
   * @returns {boolean} true when every check passes
   */
  verify({ time, usage }, hashes, lookupFn) {
    const issuer = lookupFn(this.issuerDN(), this.authorityKeyId);
    return (
      issuer &&
      (issuer.isRoot()
        ? issuer.trusted && issuer.verifySelfSigned({ time }, hashes)
        : issuer.verify(
            { time: this.valid.from, usage: "ca" },
            hashes,
            lookupFn
          )) &&
      (usage ? this.canUseFor(usage) : true) &&
      this.verifyTime(Number(time)) &&
      this.verifySignature(issuer.pubkey_unpack(), hashes) &&
      this.extension.authorityKeyIdentifier.equals(
        issuer.extension.subjectKeyIdentifier
      ) &&
      this.extension.subjectKeyIdentifier.equals(
        this.pubkey.keyid({ hash: hashes.Dstu4145le })
      )
    );
  }

  /**
   * Validate a self-signed (root) certificate: usage, validity, signature under
   * its own key, and consistency of the subject/authority key identifiers.
   * @param {{time: number, usage: string}} opts validation context
   * @param {Object<string,function>} hashes hash functions keyed by algorithm
   * @returns {boolean} true when the self-signed checks pass
   */
  verifySelfSigned({ time, usage }, hashes) {
    return usage
      ? this.canUseFor(usage)
      : this.verifyTime(time) &&
          this.verifySignature(this.pubkey_unpack(), hashes) &&
          this.pubkey
            .keyid({ hash: hashes.Dstu4145le })
            .equals(this.extension.subjectKeyIdentifier) &&
          this.extension.authorityKeyIdentifier.equals(
            this.extension.subjectKeyIdentifier
          );
  }

  /**
   * @param {number} time epoch time to test
   * @returns {boolean} true if time is within [notBefore, notAfter)
   */
  verifyTime(time) {
    return time >= this.valid.from && time < this.valid.to;
  }

  /**
   * Verify the certificate's DSTU 4145 signature over its TBSCertificate.
   * Selects the hash by the signature algorithm; a missing hash means the
   * algorithm is unsupported and verification fails.
   * @param {Object} pubkey unpacked EC public key with verify()
   * @param {Object<string,function>} hashFuncs hash functions by algorithm name
   * @returns {boolean} true if the signature is valid
   */
  verifySignature(pubkey, hashFuncs) {
    const tbs = Certificate.encodeTBS(this.ob.tbsCertificate);
    const hashFn = hashFuncs[this.signatureAlgorithm];
    if (!hashFn) return false;

    const tbsHash = hashFn(tbs);
    return pubkey.verify(tbsHash, this.ob.signature.data);
  }

  /**
   * Walk from this certificate up to (but excluding) the root, returning the
   * ordered list of issuer certificates.
   * @param {function(string, Buffer): Certificate} lookupFn issuer resolver
   * @returns {Array<Certificate>} issuers from immediate parent to root
   */
  getCompleteChain(lookupFn) {
    if (this.isRoot()) {
      return [];
    }
    const issuer = lookupFn(this.issuerDN(), this.authorityKeyId);
    return [issuer, ...issuer.getCompleteChain(lookupFn)];
  }

  /**
   * Lazily construct the EC public-key point from the stored key data.
   * @returns {Object} the unpacked public key
   */
  pubkey_unpack() {
    if (!this.pubkey) this.pubkey = this.curve.pubkey(this.pk_data);
    return this.pubkey;
  }

  /**
   * DER-encode the certificate, returning the original bytes when available.
   * @returns {Buffer} DER-encoded certificate
   */
  as_asn1() {
    if (this._raw !== undefined) {
      return this._raw;
    }

    return rfc3280.Certificate.encode(this.ob, "der");
  }

  /**
   * @returns {Buffer} DER-encoded certificate
   */
  to_asn1() {
    return this.as_asn1();
  }

  /**
   * @returns {string} PEM-armored certificate
   */
  as_pem() {
    return `-----BEGIN CERTIFICATE-----\n${b64_encode(this.to_asn1(), {
      line: 16,
      pad: true
    })}\n-----END CERTIFICATE-----`;
  }

  /**
   * @returns {string} PEM-armored certificate
   */
  to_pem() {
    return this.as_pem();
  }

  /**
   * Summarize the certificate as a plain object for display/serialization,
   * hex-encoding the key identifiers and resolving sign/encrypt usage flags.
   * @returns {Object} human-friendly certificate summary
   */
  as_dict() {
    const x = this;
    return {
      subject: x.subject,
      issuer: x.issuer,
      extension: {
        ipn: x.extension.ipn,
        authorityInfoAccess: x.extension.authorityInfoAccess,
        subjectInfoAccess: x.extension.subjectInfoAccess,
        subjectKeyIdentifier: optional(as_hex)(
          x.extension.subjectKeyIdentifier
        ),
        authorityKeyIdentifier: optional(as_hex)(
          x.extension.authorityKeyIdentifier
        )
      },
      usage: {
        sign: this.canUseFor("sign"),
        encrypt: this.canUseFor("encrypt")
      },
      valid: x.valid
    };
  }

  /**
   * @returns {{issuer: Object, serialNumber: Object}} issuer name and serial
   *   (the IssuerSerial pair used to reference this certificate)
   */
  nameSerial() {
    return {
      issuer: this.ob.tbsCertificate.issuer,
      serialNumber: this.ob.tbsCertificate.serialNumber
    };
  }

  /**
   * @returns {string} "serialHex@issuerDN" identifier for this certificate
   */
  rdnSerial() {
    return Certificate.formatRDN(
      this.ob.tbsCertificate.serialNumber,
      this.ob.tbsCertificate.issuer.value
    );
  }

  /**
   * @returns {boolean} true if issuer and subject DNs are equal (self-issued)
   */
  isRoot() {
    return this.issuerDN() === this.subjectDN();
  }

  /**
   * @returns {string} formatted issuer distinguished name
   */
  issuerDN() {
    return Certificate.formatDN(this.ob.tbsCertificate.issuer.value);
  }

  /**
   * @returns {string} formatted subject distinguished name
   */
  subjectDN() {
    return Certificate.formatDN(this.ob.tbsCertificate.subject.value);
  }

  /**
   * @returns {Buffer} DER-encoded issuer Name (used as an OCSP name hash input)
   */
  name_asn1() {
    return rfc3280.Name.encode(this.ob.tbsCertificate.issuer, "der");
  }

  /**
   * Decide whether the certificate is permitted for a given operation.
   *   - "ca": requires a basicConstraints extension with cA = true;
   *   - "sign"/"encrypt": tests the matching keyUsage bit (0x80 digitalSignature,
   *     0x08 keyAgreement) in the BIT STRING;
   *   - any other value: matched against the extendedKeyUsage OID list, and
   *     permitted by default when no EKU extension is present.
   * @param {string} op operation name to check
   * @returns {boolean} true if allowed
   */
  canUseFor(op) {
    const { keyUsage, extendedKeyUsage, basicConstraints } = this.extension;
    if (op === "ca") {
      if (!basicConstraints) {
        return false;
      }
      const basic = rfc3280.BasicConstraints.decode(basicConstraints, "der");
      return basic.cA;
    }
    const usage = {
      sign: 0x80,
      encrypt: 0x08
    };
    if (Object.prototype.hasOwnProperty.call(usage, op)) {
      const bits = UsageBits.decode(keyUsage, "der");
      const mask = usage[op];
      return (mask & bits.data[0]) === mask;
    }
    if (!extendedKeyUsage) {
      return true;
    }
    const usages = rfc3280.ExtKeyUsageSyntax.decode(extendedKeyUsage, "der");
    return usages.includes(op);
  }

  /**
   * @returns {?string} the OCSP responder URL from the AIA extension, or null
   *   when the access method is not OCSP
   */
  get ocspLink() {
    const { id, link } = this.extension.authorityInfoAccess;
    return id === "ocsp" ? link : null;
  }
}

export default Certificate;
