/* eslint-disable camelcase,no-bitwise */
/*
 * Message.js — high-level PKCS#7/CMS message model for the Ukrainian tax office.
 *
 * Wraps a CMS ContentInfo (as defined by DSTU DSTSZI GOST 34.311/GOST 28147
 * profiles) and exposes construction, parsing, signing, verification and
 * decryption of the three message types used in the local ecosystem:
 *   - "signedData"    — CAdES-style signed message with signed/unsigned attributes.
 *   - "envelopedData" — key-agreement (KARI) encrypted message.
 *   - "data"          — a bare data payload.
 *
 * Signing follows CAdES conventions: the signature is computed over the DER of
 * the signed (authenticated) attributes rather than the raw content. Supported
 * signed attributes include contentType, messageDigest, signingTime,
 * signingCertificateV2 (RFC 5035) and a content timestamp; unsigned attributes
 * carry the signature timestamp token, OCSP revocation values/refs and
 * certificate values/refs. TSP timestamp tokens are themselves Messages (RFC 3161
 * TSTInfo wrapped in signedData) and are verified recursively.
 *
 * The as_transport() helper wraps the encoded message in the tax office's
 * TRANSPORTABLE envelope (UA1_SIGN / UA1_CRYPT magics, optional CERTCRYPT).
 *
 * All EC signatures use the DSTU 4145 little-endian ("le") encoding.
 */
import { Buffer } from "buffer";

import * as dstszi2010 from "../spec/dstszi2010.js";
import * as rfc3280 from "../spec/rfc3280.js";
import rfc3161 from "../spec/rfc3161-tsp.js";
import * as certid from "../spec/rfc5035-certid.js";

import transport from "../util/transport.js";
import * as util from "../util.js";
import { useContentTsp, useSignatureTsp } from "../util/tsp.js";
import { hashAlgo, SIG_FOR_HASH } from "../util/hashes.js";
import Certificate from "./Certificate.js";
import OcspResponse from "./OcspResponse.js";
import CertificateRef from "./CertificateRef.js";

const { ContentInfo } = dstszi2010;

/**
 * Constant-time-ish byte comparison (accumulates XOR to avoid early-exit
 * timing leaks) of two buffers of equal length.
 * @param {Buffer} buf1 First buffer.
 * @param {Buffer} buf2 Second buffer.
 * @returns {boolean} True when both buffers have identical bytes.
 */
function cmp(buf1, buf2) {
  let xor = 0;
  let idx;
  for (idx = 0; idx < buf1.length && idx < buf2.length; idx += 1) {
    xor |= buf1[idx] ^ buf2[idx];
  }
  return xor === 0;
}

/**
 * Base wrapper over a CMS Attributes list ([{ type, values }]) providing keyed
 * access and append semantics.
 */
class Attrs {
  /**
   * @param {Array<{type: string, values: Array}>} list The raw attribute list.
   */
  constructor(list) {
    this.list = list;
  }

  /**
   * Builds a frozen { type: firstValue } map of the attributes for lookup.
   * Only the first value of each attribute is exposed.
   * @returns {Object} Frozen map of attribute type to its first value.
   */
  get index() {
    const ret = {};
    if (!this.list) {
      return ret;
    }
    for (let attr of this.list) {
      if (typeof attr.type === "string") {
        ret[attr.type] = attr.values[0];
      }
    }
    return Object.freeze(ret);
  }

  /**
   * Appends a value to an existing attribute of this type, or creates the
   * attribute if it does not exist yet.
   * @param {string} type Attribute type (OID name).
   * @param {*} value Encoded attribute value to store.
   * @returns {number|void} Push result of the values array when appending.
   */
  setAttr(type, value) {
    for (let attr of this.list) {
      if (attr.type === type) {
        return attr.values.push(value);
      }
    }
    this.list.push({ type, values: [value] });
  }
}
/**
 * Signed (authenticated) attributes of a signerInfo. Getters/setters transcode
 * between decoded JS values and the DER encoding stored in the attribute list.
 */
class SignedAttrs extends Attrs {
  /**
   * The message digest carried in the messageDigest attribute, stripped of its
   * OCTET STRING wrapper.
   * @returns {Buffer|null} The raw digest bytes, or null if absent/malformed.
   */
  get messageDigest() {
    const messageDigest = this.index.messageDigest;
    // Value must be a DER OCTET STRING (tag 0x04) whose length byte matches the
    // remaining bytes; otherwise it is not a well-formed digest attribute.
    if (
      !messageDigest ||
      messageDigest[0] !== 0x04 ||
      messageDigest[1] !== messageDigest.length - 2
    ) {
      return null;
    }

    return messageDigest.slice(2);
  }

  /**
   * @param {Buffer} value Raw digest bytes; stored DER-encoded as an OCTET STRING.
   */
  set messageDigest(value) {
    this.setAttr("messageDigest", dstszi2010.Data.encode(value, "der"));
  }

  /**
   * @returns {Date|null} The signing time, or null if the attribute is absent.
   */
  get signingTime() {
    const stime = this.index.signingTime;
    return (stime && rfc3280.Time.decode(stime, "der").value) || null;
  }

  /**
   * @param {Date} value Signing time; stored DER-encoded as a UTCTime.
   */
  set signingTime(value) {
    const raw = rfc3280.Time.encode({ type: "utcTime", value }, "der");
    this.setAttr("signingTime", raw);
  }

  /**
   * The CAdES content timestamp, which is itself a CMS signedData Message.
   * @returns {Message|null} Parsed timestamp Message, or null if absent.
   */
  get contentTimeStamp() {
    const raw = this.index.contentTimeStamp;
    return (raw && new Message(raw)) || null;
  }

  /**
   * @param {Buffer} value DER-encoded timestamp token to store as-is.
   */
  set contentTimeStamp(value) {
    this.setAttr("contentTimeStamp", value);
  }

  /**
   * Sets the RFC 5035 signingCertificateV2 attribute, binding the signer's
   * certificate to the signature by its ESSCertIDv2 (hash + algorithm).
   * @param {{cert: {ob: Object}, hash: Buffer, algo: string}} value Certificate
   *   object, its precomputed hash and the digest algorithm identifier.
   */
  set signingCertificateV2(value) {
    this.setAttr(
      "signingCertificateV2",
      certid.SigningCertificateV2.wrap(value.cert.ob, value.hash, value.algo)
    );
  }

  /**
   * @param {string} value Content type OID name; stored DER-encoded.
   */
  set contentType(value) {
    const raw = dstszi2010.ContentType.encode(value, "der");
    this.setAttr("contentType", raw);
  }
}

/**
 * Unsigned (unauthenticated) attributes of a signerInfo: the signature
 * timestamp token and CAdES-C revocation/certificate values and references.
 */
class UnsignedAttrs extends Attrs {
  /**
   * The RFC 3161 signature timestamp token, wrapped as a CMS Message.
   * @returns {Message|null} Parsed timestamp Message, or null if absent.
   */
  get timeStampToken() {
    const raw = this.index.timeStampToken;
    return (raw && new Message(raw)) || null;
  }

  /**
   * @param {Buffer} value DER-encoded timestamp token to store as-is.
   */
  set timeStampToken(value) {
    this.setAttr("timeStampToken", value);
  }

  /**
   * @returns {Array} Decoded OCSP responses from the revocationValues attribute,
   *   or an empty array if absent.
   */
  get revocationValues() {
    const raw = this.index.revocationValues;
    return (raw && OcspResponse.fromCades(raw)) || [];
  }

  /**
   * @param {Array} value OCSP responses to store as CAdES revocationValues.
   */
  set revocationValues(value) {
    this.setAttr("revocationValues", OcspResponse.toCades(value));
  }

  /**
   * @returns {Array} Decoded OCSP response references from the revocationRefs
   *   attribute, or an empty array if absent.
   */
  get revocationRefs() {
    const raw = this.index.revocationRefs;
    return (raw && OcspResponse.Ref.fromCades(raw)) || [];
  }

  /**
   * @param {Array} value OCSP references to store as CAdES revocationRefs.
   */
  set revocationRefs(value) {
    this.setAttr("revocationRefs", OcspResponse.Ref.toCades(value));
  }

  /**
   * @param {Array} value Certificate references to store as CAdES certificateRefs.
   */
  set certificateRefs(value) {
    this.setAttr("certificateRefs", CertificateRef.toCades(value));
  }

  /**
   * @param {Array} value Certificates to store as CAdES certificateValues.
   */
  set certificateValues(value) {
    this.setAttr("certificateValues", Certificate.List.toCades(value));
  }
}

/**
 * A CMS ContentInfo message: signedData, envelopedData or bare data.
 * Construct from a DER Buffer to parse, or from a descriptor object to build.
 */
class Message {
  /** Error thrown when a required signer/recipient certificate cannot be found. */
  static ENOCERT = class ENOCERT extends Error {
    code = "ENOCERT";
  };

  /**
   * @param {Buffer|Object} asn1Ob Either a DER-encoded ContentInfo Buffer to
   *   parse, or a descriptor object ({ type, ... }) to build a new message from.
   */
  constructor(asn1Ob) {
    if (Buffer.isBuffer(asn1Ob)) {
      this.parse(asn1Ob);
    } else if (typeof asn1Ob === "object") {
      this.constructMessage(asn1Ob);
    }
  }

  /**
   * Dispatches to the type-specific builder and stores the associated certificate.
   * @param {Object} ob Descriptor with a `type` of "signedData"/"envelopedData"/"data".
   * @returns {void}
   */
  constructMessage(ob) {
    if (ob.type === "signedData") {
      this.constructSigned(ob);
    }
    if (ob.type === "envelopedData") {
      this.constructEnveloped(ob);
    }
    if (ob.type === "data") {
      this.constructData(ob);
    }
    this.cert = ob.cert;
  }

  /**
   * Builds a bare "data" ContentInfo.
   * @param {{type: string, data: Buffer}} ob Descriptor with the payload.
   * @returns {void}
   */
  constructData(ob) {
    const wrap = {
      contentType: ob.type,
      content: ob.data
    };
    this.wrap = wrap;
  }

  /**
   * Builds an envelopedData ContentInfo using DSTU 4145 key agreement (KARI).
   * The payload is symmetrically encrypted (Gost28147-cfb) with a content
   * encryption key that is wrapped for the recipient via cofactor DH + GOST KDF.
   * @param {Object} ob Descriptor with { cert, toCert, crypter, data, algo, type }.
   * @returns {void}
   */
  constructEnveloped(ob) {
    const { cert } = ob;
    const algo = cert.ob.tbsCertificate.subjectPublicKeyInfo.algorithm;
    // dke (DKE substitution S-box) is taken from the originator certificate's
    // public key parameters and echoed into the content encryption params.
    const { dke } = algo.parameters;

    // Encrypt the payload; enc yields ukm, wrapped CEK (wcek), IV and ciphertext.
    const enc = ob.crypter.encrypt(ob.data, ob.toCert, ob.algo);
    const kari = {
      version: 3,
      originator: {
        type: "issuerAndSerialNumber",
        value: cert.nameSerial()
      },
      ukm: enc.ukm,
      keyEncryptionAlgorithm: {
        algorithm: "dhSinglePass-cofactorDH-gost34311kdf",
        parameters: {
          algorithm: "Gost28147-cfb-wrap",
          parameters: null
        }
      },
      recipientEncryptedKeys: [
        {
          rid: {
            type: "issuerAndSerialNumber",
            value: ob.toCert.nameSerial()
          },
          encryptedKey: enc.wcek
        }
      ]
    };

    const wrap = {
      contentType: ob.type,
      content: {
        version: 2,
        recipientInfos: [
          {
            type: "kari",
            value: kari
          }
        ],
        encryptedContentInfo: {
          contentType: "data",
          encryptedContent: enc.data,
          contentEncryptionAlgorithm: {
            algorithm: "Gost28147-cfb",
            parameters: {
              type: "params",
              value: {
                iv: enc.iv,
                dke
              }
            }
          }
        }
      }
    };
    this.wrap = wrap;
  }

  /**
   * Builds a signedData ContentInfo and populates its CAdES signed attributes.
   * If no precomputed signature (signB) is supplied, signs over the DER of the
   * authenticated attributes; optionally attaches content and signature TSP tokens.
   * @param {Object} ob Descriptor with { type, data|dataHash, hash, signer,
   *   cert, signB, tspB, tspTokenB, signTime }.
   * @returns {void}
   */
  constructSigned(ob) {
    // Digest of the content: use a precomputed dataHash if given, else hash data.
    const digestB = ob.dataHash || (ob.data && ob.hash(ob.data));
    let { signB } = ob;
    const { tspB, tspTokenB } = ob;
    // Map the hash function to its DSTU digest algorithm OID name (e.g. Gost34311).
    const digestAlgo = hashAlgo(ob.hash);
    // Pair the digest with a compatible DSTU 4145 signature OID.
    //   - Gost34311   -> "Dstu4145le"                  (legacy profile)
    //   - Dstu7564-*  -> "Dstu4145le-Dstu7564-*-pb"    (Kupyna profile, PB)
    // Verifiers reject a mismatch here as "Невірний підпис(35)". jkurwa only
    // supports polynomial-basis (PB) curves (lib/curve.js, lib/standard.js),
    // so when a `-pb` variant exists it is always the correct choice — the
    // non-`-pb` Kupyna OIDs are reserved for the ONB profile this library
    // never emits. The signer's certificate can be signed with either the
    // legacy Dstu4145le or the newer -pb OID; that has no bearing on which
    // OID must go into this signerInfo.
    const sigCandidates = SIG_FOR_HASH[digestAlgo] || ["Dstu4145le"];
    const sigAlgo =
      sigCandidates.find(oid => oid.endsWith("-pb")) || sigCandidates[0];

    const wrap = {
      contentType: ob.type,
      content: {
        version: 1,
        digestAlgorithms: [{ algorithm: digestAlgo }],
        // Omit the content for a detached signature (when only a hash is known).
        contentInfo: ob.data
          ? { contentType: "data", content: ob.data }
          : { contentType: "data" },
        certificate: [ob.cert.ob],
        signerInfos: [
          {
            version: 1,
            sid: {
              type: "issuerAndSerialNumber",
              value: ob.cert.nameSerial()
            },
            digestAlgorithm: { algorithm: digestAlgo },
            digestEncryptionAlgorithm: { algorithm: sigAlgo },
            encryptedDigest: signB
          }
        ]
      }
    };
    this.wrap = wrap;
    this.attrs = [];
    this.uattrs = [];
    this.parseAttrs();
    // Bind the signer certificate to the signature (RFC 5035 signingCertificateV2)
    // using a hash of the DER certificate under the same digest algorithm.
    this.pattrs.signingCertificateV2 = {
      cert: ob.cert,
      hash: ob.hash(ob.cert.as_asn1()),
      algo: digestAlgo
    };
    this.pattrs.contentType = "data";
    this.pattrs.messageDigest = digestB;
    if (tspB) {
      this.pattrs.contentTimeStamp = tspB;
    }
    // signTime is a Unix epoch in seconds; default to now when unspecified.
    this.pattrs.signingTime =
      ob.signTime === undefined
        ? new Date(Date.now())
        : new Date(1000 * ob.signTime);
    this.saveAttrs();

    // With no precomputed signature, sign the assembled authenticated attributes.
    if (!signB) {
      this.addSignature(ob.hash, ob.signer);
    }
    this.addSignatureToken(tspTokenB);
  }

  /**
   * Signs the message and stores the resulting encryptedDigest.
   * The signature is computed over the hash of the signed attributes (mhash).
   * @param {function(Buffer): Buffer} hash_f Digest function.
   * @param {{sign: function(Buffer, string): Buffer}} signer Private-key signer.
   * @returns {void}
   */
  addSignature(hash_f, signer) {
    this.signature = signer.sign(this.mhash(hash_f), "le");
    this.saveAttrs();
  }

  /**
   * Attaches a signature timestamp token as an unsigned attribute, if provided.
   * @param {Buffer} [tspTokenB] DER-encoded RFC 3161 timestamp token.
   * @returns {void}
   */
  addSignatureToken(tspTokenB) {
    if (!tspTokenB) {
      return;
    }
    this.puattrs.timeStampToken = tspTokenB;
    this.saveAttrs();
  }

  /**
   * Adds full OCSP responses as the revocationValues unsigned attribute (CAdES-XL).
   * @param {Array} list OCSP responses; no-op when empty.
   * @returns {void}
   */
  addOcspResponses(list) {
    if (!list.length) {
      return;
    }
    this.puattrs.revocationValues = list;
    this.saveAttrs();
  }

  /**
   * Adds OCSP response references as the revocationRefs unsigned attribute (CAdES-C).
   * @param {Array} list OCSP references; no-op when empty.
   * @returns {void}
   */
  addOcspHashes(list) {
    if (!list.length) {
      return;
    }
    this.puattrs.revocationRefs = list;
    this.saveAttrs();
  }

  /**
   * Adds certificate references as the certificateRefs unsigned attribute (CAdES-C).
   * @param {Array} list Certificate references; no-op when empty.
   * @returns {void}
   */
  addCertRefs(list) {
    if (!list.length) {
      return;
    }
    this.puattrs.certificateRefs = list;
    this.saveAttrs();
  }

  /**
   * Adds full certificates as the certificateValues unsigned attribute (CAdES-XL).
   * @param {Array} list Certificates; no-op when empty.
   * @returns {void}
   */
  addCertValues(list) {
    if (!list.length) {
      return;
    }
    this.puattrs.certificateValues = list;
    this.saveAttrs();
  }

  /** @returns {string} The ContentInfo contentType (message type). */
  get type() {
    return this.wrap.contentType;
  }

  /** @returns {Object} The inner content of the ContentInfo. */
  get info() {
    return this.wrap.content;
  }

  /**
   * Parses a DER-encoded ContentInfo and extracts type-specific fields
   * (encryption params for envelopedData; signer attributes for signedData).
   * @param {Buffer} data DER-encoded ContentInfo.
   * @returns {void}
   */
  parse(data) {
    this.wrap = ContentInfo.decode(data, "der");

    if (this.type === "envelopedData") {
      // extract encryption params from asn1
      this.enc_info = this.info.encryptedContentInfo;
      this.enc_params =
        this.enc_info.contentEncryptionAlgorithm.parameters.value;
      if (this.info.recipientInfos.length === 1) {
        this.rki = this.info.recipientInfos[0].value;
      }
      this.enc_contents = this.info.encryptedContentInfo.encryptedContent;
    }
    if (this.type === "signedData" && this.info.signerInfos.length) {
      this.attrs = this.info.signerInfos[0].authenticatedAttributes;
      this.uattrs = this.info.signerInfos[0].unauthenticatedAttributes;
    }
    this.parseAttrs();
  }

  /**
   * Computes the digest that the signature covers. Per CAdES, this is the hash
   * of the DER-encoded authenticated attributes when present, otherwise the
   * hash of the raw content (plain PKCS#7 signature).
   * @param {function(Buffer): Buffer} hash_f Digest function.
   * @returns {Buffer} Digest to be signed/verified.
   */
  mhash(hash_f) {
    let dataToSign;
    if (this.attrs) {
      dataToSign = dstszi2010.Attributes.encode(this.attrs, "der");
    } else {
      dataToSign = this.info.contentInfo.content;
    }
    return hash_f(dataToSign);
  }

  /**
   * Wraps the raw signed/unsigned attribute lists in their typed helpers.
   * @returns {void}
   */
  parseAttrs() {
    this.pattrs = new SignedAttrs(this.attrs);
    this.puattrs = new UnsignedAttrs(this.uattrs);
  }

  /**
   * Writes the current attribute lists back into the first signerInfo.
   * Unauthenticated attributes are only written when non-empty (the field is
   * OPTIONAL and an empty SET would change the encoding).
   * @returns {void}
   */
  saveAttrs() {
    this.info.signerInfos[0].authenticatedAttributes = this.pattrs.list;
    if (this.puattrs.list.length) {
      this.info.signerInfos[0].unauthenticatedAttributes = this.puattrs.list;
    }
  }

  /**
   * Verifies the CAdES signed attributes: message digest, signing time within
   * the certificate validity window, and (per opts.tsp) content/signature
   * timestamp tokens.
   * @param {function(Buffer): Buffer} hash_f Digest function.
   * @param {function} lookupCert Resolves a signer RDN/key id to a Certificate.
   * @param {function} lookupCA Resolves an issuer to a CA certificate.
   * @param {Object} [opts] Options; opts.tsp selects which timestamps to check.
   * @returns {boolean} True when all present attributes verify.
   */
  verifyAttrs(hash_f, lookupCert, lookupCA, opts = {}) {
    if (!this.attrs) {
      return true;
    }

    let ok;
    ok = this.verifyAttrDigest(this.pattrs.messageDigest, hash_f);
    ok = ok && this.verifySigningTime(this.pattrs.signingTime, lookupCert);
    if (useContentTsp(opts.tsp)) {
      ok =
        ok &&
        this.verifyTimestampToken(
          this.pattrs.contentTimeStamp,
          hash_f,
          lookupCert,
          lookupCA,
          "content"
        );
    }
    if (useSignatureTsp(opts.tsp)) {
      ok =
        ok &&
        this.verifyTimestampToken(
          this.puattrs.timeStampToken,
          hash_f,
          lookupCert,
          lookupCA,
          "signature"
        );
    }

    return ok;
  }

  /**
   * Checks that the messageDigest attribute matches the actual content hash.
   * @param {Buffer} dgst Digest carried in the signed attributes.
   * @param {function(Buffer): Buffer} hash_f Digest function.
   * @returns {boolean} True when the digests match.
   */
  verifyAttrDigest(dgst, hash_f) {
    if (!dgst) {
      return false;
    }
    const dataToSign = this.info.contentInfo.content;
    const hashbuf = hash_f(dataToSign);
    return cmp(dgst, hashbuf);
  }

  /**
   * Checks that the claimed signing time falls within the signer certificate's
   * validity period. Absent time is treated as acceptable.
   * @param {Date|null} time Signing time from the signed attributes.
   * @param {function} lookupCert Resolver for the signer certificate.
   * @returns {boolean} True when the time is within validity (or absent).
   */
  verifySigningTime(time, lookupCert) {
    if (!time) {
      return true;
    }
    const x509 = this.signer(lookupCert);
    return time >= x509.valid.from && time <= x509.valid.to;
  }

  /**
   * Verifies an RFC 3161 timestamp token (itself a signedData Message): that it
   * is properly signed, that its signer certificate is valid for timeStamping at
   * the token's genTime, that the imprint algorithm matches, and that the imprint
   * equals the hash of the timestamped data (content or signature).
   * @param {Message|null} msg The timestamp token Message; null passes trivially.
   * @param {function(Buffer): Buffer} hash_f Digest function.
   * @param {function} lookupCert Resolver for the TSA signer certificate.
   * @param {function} lookupCA Resolver for the TSA issuer certificate.
   * @param {string} imprintOf Property name ("content"/"signature") whose value
   *   the imprint must hash to.
   * @returns {boolean} True when the token verifies.
   */
  verifyTimestampToken(msg, hash_f, lookupCert, lookupCA, imprintOf) {
    if (!msg) {
      return true;
    }
    // The token must be a valid CMS signature over its TSTInfo.
    const isSigned = msg.verify(hash_f, lookupCert, lookupCA);
    if (!isSigned) {
      return false;
    }
    const token = rfc3161.TSTInfo.decode(msg.content, "der");
    // The TSA certificate must be valid at genTime and carry the timeStamping EKU.
    const signerValid = msg
      .signer(lookupCert)
      .verify(
        { time: token.genTime, usage: "timeStamping" },
        { Dstu4145le: hash_f },
        lookupCA
      );
    if (!signerValid) {
      return false;
    }

    // Imprint hash algorithm must match ours, and the imprint must cover the
    // corresponding data (message content for content-TSP, signature for signature-TSP).
    if (token.messageImprint.hashAlgorithm.algorithm !== hashAlgo(hash_f)) {
      return false;
    }
    return cmp(token.messageImprint.hashedMessage, hash_f(this[imprintOf]));
  }

  /**
   * @returns {string} The signerInfo digest algorithm OID name, defaulting to
   *   "Gost34311" when not present.
   */
  get digestAlgo() {
    const [signerInfo] = this.info.signerInfos;
    return (
      (signerInfo &&
        signerInfo.digestAlgorithm &&
        signerInfo.digestAlgorithm.algorithm) ||
      "Gost34311"
    );
  }

  /** @returns {Buffer} The raw signature bytes (encryptedDigest) of the signer. */
  get signature() {
    return this.info.signerInfos[0].encryptedDigest;
  }

  /** @param {Buffer} value Signature bytes to store as encryptedDigest. */
  set signature(value) {
    this.info.signerInfos[0].encryptedDigest = value;
  }

  /** @returns {Buffer} The signed content payload. */
  get content() {
    return this.info.contentInfo.content;
  }

  /**
   * Collects the signer identities of this message and, recursively, of every
   * embedded timestamp token, so all certificates needed to verify can be fetched.
   * @returns {Array} Signer RDNs/key ids of this message and its TSP tokens.
   */
  get signedWithCerts() {
    const tokens = [this.pattrs.contentTimeStamp, this.puattrs.timeStampToken]
      .filter(msg => msg)
      .map(msg => msg.signedWithCerts);
    return [this.signerRDN].concat(...tokens);
  }

  /**
   * The signer identity from the first signerInfo.
   * @returns {Object|null} An issuerAndSerialNumber value, a { keyid } for a
   *   subjectKeyIdentifier, or null for an unrecognized sid type.
   */
  get signerRDN() {
    const [
      {
        sid: { type, value }
      }
    ] = this.info.signerInfos;
    if (type === "issuerAndSerialNumber") {
      return value;
    }
    if (type === "subjectKeyIdentifier") {
      return { keyid: value };
    }
    return null;
  }

  /**
   * Resolves the signer certificate: prefers one embedded in the message,
   * otherwise looks it up by the signer RDN via the caller-supplied resolver.
   * @param {function} lookupCert Resolver from RDN/key id to a Certificate.
   * @returns {Certificate} The signer certificate.
   * @throws {Message.ENOCERT} When no certificate can be resolved.
   */
  signer(lookupCert) {
    const [certificate] = this.info.certificate || [];
    if (certificate) {
      return new Certificate(certificate);
    }
    const query = this.signerRDN;
    const pubkey = query && lookupCert(query);
    if (pubkey) {
      return pubkey;
    }
    throw new Message.ENOCERT();
  }

  /**
   * @returns {Date|null} genTime of the signature timestamp token, or null if none.
   */
  get tokenTime() {
    const msg = this.puattrs.timeStampToken;
    if (!msg) {
      return null;
    }
    const token = rfc3161.TSTInfo.decode(msg.info.contentInfo.content, "der");
    return token.genTime;
  }

  /**
   * @returns {Date|null} genTime of the content timestamp token, or null if none.
   */
  get contentTime() {
    const msg = this.pattrs.contentTimeStamp;
    if (!msg) {
      return null;
    }
    const token = rfc3161.TSTInfo.decode(msg.info.contentInfo.content, "der");
    return token.genTime;
  }

  /**
   * The recipient identifier of an envelopedData message.
   * @returns {Object} The rid (recipient identifier) of the first encrypted key.
   * @throws {Message.ENOCERT} When the recipient info is not key-agreement (kari).
   */
  get receiverKey() {
    const ri = this.info.recipientInfos[0];
    if (ri.type !== "kari") {
      throw new Message.ENOCERT();
    }
    return ri.value.recipientEncryptedKeys[0].rid;
  }

  /**
   * Verifies the signature over this message: first the signed attributes, then
   * the EC (DSTU 4145 little-endian) signature over their digest.
   * @param {function(Buffer): Buffer} hash_f Digest function.
   * @param {function} lookupCert Resolver for the signer certificate.
   * @param {function} lookupCA Resolver for the issuer certificate.
   * @param {Object} [opts] Options forwarded to attribute verification (tsp).
   * @returns {boolean} True when the message is authentic.
   */
  verify(hash_f, lookupCert, lookupCA, opts = {}) {
    const hash = this.mhash(hash_f);

    if (!this.verifyAttrs(hash_f, lookupCert, lookupCA, opts)) {
      return false;
    }
    return this.signer(lookupCert).pubkey.verify(hash, this.signature, "le");
  }

  /**
   * Decrypts an envelopedData message. Recovers the originator public key
   * (either by looked-up certificate or from an embedded originatorKey), then
   * runs key agreement to unwrap the CEK and decrypt the content.
   * @param {Object} crypter Cipher/curve provider with decrypt() and curve.pubkey().
   * @param {Object} algo Symmetric algorithm parameters.
   * @param {function} lookupCert Resolver for the originator certificate.
   * @returns {Buffer} The decrypted payload.
   * @throws {Message.ENOCERT} When recipient info is not kari or the key is missing.
   */
  decrypt(crypter, algo, lookupCert) {
    let pubkey;
    const ri = this.info.recipientInfos[0];
    if (ri.type !== "kari") {
      throw new Message.ENOCERT();
    }

    if (ri.value.originator.type === "issuerAndSerialNumber") {
      pubkey = lookupCert(ri.value.originator.value);
      if (!pubkey) {
        throw new Message.ENOCERT();
      }
      pubkey = pubkey.pubkey; // eslint-disable-line prefer-destructuring
    }
    if (ri.value.originator.type === "originatorKey") {
      const { originator } = this.info.recipientInfos[0].value;
      // Strip the 2-byte BIT STRING prefix, restore the leading zero and load
      // the raw ephemeral public key onto the curve.
      pubkey = originator.value.publicKey.data.slice(2);
      pubkey = crypter.curve.pubkey(util.add_zero(pubkey, true), "buf8");
    }
    const enc = this.info.encryptedContentInfo;

    const enc_param = enc.contentEncryptionAlgorithm.parameters.value;

    const rp = this.info.recipientInfos[0].value.recipientEncryptedKeys[0];
    const p = {
      ukm: this.info.recipientInfos[0].value.ukm,
      iv: enc_param.iv,
      wcek: rp.encryptedKey
    };
    return crypter.decrypt(enc.encryptedContent, pubkey, p, algo);
  }

  /**
   * @returns {Buffer} The DER-encoded ContentInfo of this message.
   */
  as_asn1() {
    const buf = ContentInfo.encode(this.wrap, "der");
    return buf;
  }

  /**
   * Wraps the encoded message in the tax office TRANSPORTABLE envelope. The
   * magic tags the payload as a signature (UA1_SIGN) or ciphertext (UA1_CRYPT);
   * an optional leading CERTCRYPT document carries the sender certificate.
   * @param {Object} opts Transport options passed to the encoder.
   * @param {boolean} [addCert] When true, prepend the sender certificate.
   * @returns {Buffer} The encoded transport container.
   */
  as_transport(opts, addCert) {
    const docs = [];

    let magic;

    if (this.type === "signedData") {
      magic = "UA1_SIGN";
    }
    if (this.type === "envelopedData") {
      magic = "UA1_CRYPT";
    }
    if (addCert) {
      docs.push({ type: "CERTCRYPT", contents: this.cert.as_asn1() });
    }
    docs.push({ type: magic, contents: this.as_asn1() });
    return transport.encode(docs, opts);
  }
}

export default Message;
