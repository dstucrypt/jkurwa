/* eslint-disable camelcase,no-bitwise */
const Buffer = require("buffer").Buffer;

const dstszi2010 = require("../spec/dstszi2010.js");
const rfc3280 = require("../spec/rfc3280");
const rfc3161 = require("../spec/rfc3161-tsp");
const certid = require("../spec/rfc5035-certid.js");

const transport = require("../util/transport");
const util = require("../util.js");
const { useContentTsp, useSignatureTsp } = require("../util/tsp");
const Certificate = require("./Certificate.js");
const OcspResponse = require("./OcspResponse.js");
const CertificateRef = require("./CertificateRef");

const { ContentInfo } = dstszi2010;

class ENOCERT extends Error {}

function cmp(buf1, buf2) {
  let xor = 0;
  let idx = 0;
  for (idx = 0; idx < buf1.length && idx < buf2.length; idx += 1) {
    xor |= buf1[idx] ^ buf2[idx];
  }
  return xor === 0;
}

class Attrs {
  constructor(list) {
    this.list = list;
  }

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

  setAttr(type, value) {
    for (let attr of this.list) {
      if (attr.type === type) {
        return attr.values.push(value);
      }
    }
    this.list.push({ type, values: [value] });
  }
}
class SignedAttrs extends Attrs {
  get messageDigest() {
    const messageDigest = this.index.messageDigest;
    if (
      !messageDigest ||
      messageDigest[0] !== 0x04 ||
      messageDigest[1] !== messageDigest.length - 2
    ) {
      return null;
    }

    return messageDigest.slice(2);
  }

  set messageDigest(value) {
    this.setAttr("messageDigest", dstszi2010.Data.encode(value, "der"));
  }

  get signingTime() {
    const stime = this.index.signingTime;
    return (stime && rfc3280.Time.decode(stime, "der").value) || null;
  }

  set signingTime(value) {
    const raw = rfc3280.Time.encode({ type: "utcTime", value }, "der");
    this.setAttr("signingTime", raw);
  }

  get contentTimeStamp() {
    const raw = this.index.contentTimeStamp;
    return (raw && new Message(raw)) || null;
  }

  set contentTimeStamp(value) {
    this.setAttr("contentTimeStamp", value);
  }

  set signingCertificateV2(value) {
    this.setAttr(
      "signingCertificateV2",
      certid.SigningCertificateV2.wrap(value.cert.ob, value.hash)
    );
  }

  set contentType(value) {
    const raw = dstszi2010.ContentType.encode(value, "der");
    this.setAttr("contentType", raw);
  }
}

class UnsignedAttrs extends Attrs {
  get timeStampToken() {
    const raw = this.index.timeStampToken;
    return (raw && new Message(raw)) || null;
  }

  set timeStampToken(value) {
    this.setAttr("timeStampToken", value);
  }

  get revocationValues() {
    const raw = this.index.revocationValues;
    return (raw && OcspResponse.fromCades(raw)) || [];
  }

  set revocationValues(value) {
    this.setAttr("revocationValues", OcspResponse.toCades(value));
  }

  get revocationRefs() {
    const raw = this.index.revocationRefs;
    return (raw && OcspResponse.Ref.fromCades(raw)) || [];
  }

  set revocationRefs(value) {
    this.setAttr("revocationRefs", OcspResponse.Ref.toCades(value));
  }

  set certificateRefs(value) {
    this.setAttr("certificateRefs", CertificateRef.toCades(value));
  }

  set certificateValues(value) {
    this.setAttr("certificateValues", Certificate.List.toCades(value));
  }
}

class Message {
  constructor(asn1Ob) {
    if (Buffer.isBuffer(asn1Ob)) {
      this.parse(asn1Ob);
    } else if (typeof asn1Ob === "object") {
      this.constructMessage(asn1Ob);
    }
  }

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

  constructData(ob) {
    const wrap = {
      contentType: ob.type,
      content: ob.data
    };
    this.wrap = wrap;
  }

  constructEnveloped(ob) {
    const { cert } = ob;
    const algo = cert.ob.tbsCertificate.subjectPublicKeyInfo.algorithm;
    const { dke } = algo.parameters;

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

  constructSigned(ob) {
    const digestB = ob.dataHash || (ob.data && ob.hash(ob.data));
    let { signB } = ob;
    const { tspB, tspTokenB } = ob;

    const wrap = {
      contentType: ob.type,
      content: {
        version: 1,
        digestAlgorithms: [{ algorithm: "Gost34311" }],
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
            digestAlgorithm: { algorithm: "Gost34311" },
            digestEncryptionAlgorithm: { algorithm: "Dstu4145le" },
            encryptedDigest: signB
          }
        ]
      }
    };
    this.wrap = wrap;
    this.attrs = [];
    this.uattrs = [];
    this.parseAttrs();
    this.pattrs.signingCertificateV2 = {
      cert: ob.cert,
      hash: ob.hash(ob.cert.as_asn1())
    };
    this.pattrs.contentType = "data";
    this.pattrs.messageDigest = digestB;
    if (tspB) {
      this.pattrs.contentTimeStamp = tspB;
    }
    this.pattrs.signingTime =
      ob.signTime === undefined
        ? new Date(Date.now())
        : new Date(1000 * ob.signTime);
    this.saveAttrs();

    if (!signB) {
      this.addSignature(ob.hash, ob.signer);
    }
    this.addSignatureToken(tspTokenB);
  }

  addSignature(hash_f, signer) {
    this.signature = signer.sign(this.mhash(hash_f), "le");
    this.saveAttrs();
  }

  addSignatureToken(tspTokenB) {
    if (!tspTokenB) {
      return;
    }
    this.puattrs.timeStampToken = tspTokenB;
    this.saveAttrs();
  }

  addOcspResponses(list) {
    if (!list.length) {
      return;
    }
    this.puattrs.revocationValues = list;
    this.saveAttrs();
  }

  addOcspHashes(list) {
    if (!list.length) {
      return;
    }
    this.puattrs.revocationRefs = list;
    this.saveAttrs();
  }

  addCertRefs(list) {
    if (!list.length) {
      return;
    }
    this.puattrs.certificateRefs = list;
    this.saveAttrs();
  }

  addCertValues(list) {
    if (!list.length) {
      return;
    }
    this.puattrs.certificateValues = list;
    this.saveAttrs();
  }

  get type() {
    return this.wrap.contentType;
  }

  get info() {
    return this.wrap.content;
  }

  parse(data) {
    this.wrap = ContentInfo.decode(data, "der");

    if (this.type === "envelopedData") {
      // extract encryption params from asn1
      this.enc_info = this.info.encryptedContentInfo;
      this.enc_params = this.enc_info.contentEncryptionAlgorithm.parameters.value;
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

  mhash(hash_f) {
    let dataToSign;
    if (this.attrs) {
      dataToSign = dstszi2010.Attributes.encode(this.attrs, "der");
    } else {
      dataToSign = this.info.contentInfo.content;
    }
    return hash_f(dataToSign);
  }

  parseAttrs() {
    this.pattrs = new SignedAttrs(this.attrs);
    this.puattrs = new UnsignedAttrs(this.uattrs);
  }

  saveAttrs() {
    this.info.signerInfos[0].authenticatedAttributes = this.pattrs.list;
    if (this.puattrs.list.length) {
      this.info.signerInfos[0].unauthenticatedAttributes = this.puattrs.list;
    }
  }

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

  verifyAttrDigest(dgst, hash_f) {
    if (!dgst) {
      return false;
    }
    const dataToSign = this.info.contentInfo.content;
    const hashbuf = hash_f(dataToSign);
    return cmp(dgst, hashbuf);
  }

  verifySigningTime(time, lookupCert) {
    if (!time) {
      return true;
    }
    const x509 = this.signer(lookupCert);
    return time >= x509.valid.from && time <= x509.valid.to;
  }

  verifyTimestampToken(msg, hash_f, lookupCert, lookupCA, imprintOf) {
    if (!msg) {
      return true;
    }
    const isSigned = msg.verify(hash_f, lookupCert, lookupCA);
    if (!isSigned) {
      return false;
    }
    const token = rfc3161.TSTInfo.decode(msg.content, "der");
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

    if (token.messageImprint.hashAlgorithm.algorithm !== "Gost34311") {
      return false;
    }
    return cmp(token.messageImprint.hashedMessage, hash_f(this[imprintOf]));
  }

  get signature() {
    return this.info.signerInfos[0].encryptedDigest;
  }

  set signature(value) {
    this.info.signerInfos[0].encryptedDigest = value;
  }

  get content() {
    return this.info.contentInfo.content;
  }

  get signedWithCerts() {
    const tokens = [this.pattrs.contentTimeStamp, this.puattrs.timeStampToken]
      .filter(msg => msg)
      .map(msg => msg.signedWithCerts);
    return [this.signerRDN].concat(...tokens);
  }

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
    throw new ENOCERT();
  }

  get tokenTime() {
    const msg = this.puattrs.timeStampToken;
    if (!msg) {
      return null;
    }
    const token = rfc3161.TSTInfo.decode(msg.info.contentInfo.content, "der");
    return token.genTime;
  }

  get contentTime() {
    const msg = this.pattrs.contentTimeStamp;
    if (!msg) {
      return null;
    }
    const token = rfc3161.TSTInfo.decode(msg.info.contentInfo.content, "der");
    return token.genTime;
  }

  get receiverKey() {
    const ri = this.info.recipientInfos[0];
    if (ri.type !== "kari") {
      throw new ENOCERT();
    }
    return ri.value.recipientEncryptedKeys[0].rid;
  }

  verify(hash_f, lookupCert, lookupCA, opts = {}) {
    const hash = this.mhash(hash_f);

    if (!this.verifyAttrs(hash_f, lookupCert, lookupCA, opts)) {
      return false;
    }
    return this.signer(lookupCert).pubkey.verify(hash, this.signature, "le");
  }

  decrypt(crypter, algo, lookupCert) {
    let pubkey;
    const ri = this.info.recipientInfos[0];
    if (ri.type !== "kari") {
      throw new ENOCERT();
    }

    if (ri.value.originator.type === "issuerAndSerialNumber") {
      pubkey = lookupCert(ri.value.originator.value);
      if (!pubkey) {
        throw new ENOCERT();
      }
      pubkey = pubkey.pubkey; // eslint-disable-line prefer-destructuring
    }
    if (ri.value.originator.type === "originatorKey") {
      const { originator } = this.info.recipientInfos[0].value;
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

  as_asn1() {
    const buf = ContentInfo.encode(this.wrap, "der");
    return buf;
  }

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

module.exports = Message;
module.exports.ENOCERT = ENOCERT;
