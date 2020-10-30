/* eslint-disable camelcase,no-bitwise */
const Buffer = require("buffer").Buffer;

const dstszi2010 = require("../spec/dstszi2010.js");
const rfc3280 = require("../spec/rfc3280");
const rfc3161 = require("../spec/rfc3161-tsp");
const certid = require("../spec/rfc5035-certid.js");

const transport = require("../util/transport");
const util = require("../util.js");
const Certificate = require("./Certificate.js");

const { ContentInfo } = dstszi2010;

const ENOCERT = function ENOCERT() {};
ENOCERT.prototype = new Error();

const Message = function Message(asn1Ob) {
  this.type = null;
  this.info = null;
  if (Buffer.isBuffer(asn1Ob)) {
    this.parse(asn1Ob);
  } else if (typeof asn1Ob === "object") {
    this.construct(asn1Ob);
  }
};

Message.prototype.construct = function constructor(ob) {
  if (ob.type === "signedData") {
    this.constructSigned(ob);
  }
  if (ob.type === "envelopedData") {
    this.constructEnveloped(ob);
  }
  if (ob.type === "data") {
    this.constructData(ob);
  }
  this.info = this.wrap.content;
  this.type = this.wrap.contentType;
  this.cert = ob.cert;
};

Message.prototype.constructData = function constructData(ob) {
  const wrap = {
    contentType: ob.type,
    content: ob.data
  };
  this.wrap = wrap;
  this.info = wrap.content;
};

Message.prototype.constructEnveloped = function constructEnveloped(ob) {
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
  this.info = wrap.content;
};

Message.prototype.constructSigned = function constructSigned(ob) {
  const digestB = ob.dataHash || ob.hash(ob.data);
  let { signB } = ob;
  const { tspB, tspTokenB } = ob;

  const authenticatedAttributes = [
    this.certv2(ob.cert, ob.hash(ob.cert.as_asn1())),
    this.contentType("data"),
    this.digestAttr(digestB),
    tspB && this.tspAttr(tspB),
    this.timeAttr(ob.signTime)
  ].filter(attr => Boolean(attr));
  if (signB === undefined) {
    this.attrs = authenticatedAttributes;
    this.info = {
      contentInfo: { content: ob.data }
    };
    const digestS = this.mhash(ob.hash);
    signB = ob.signer.sign(digestS, "le");
  }

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
          encryptedDigest: signB,
          authenticatedAttributes
        }
      ]
    }
  };
  this.wrap = wrap;
  this.info = wrap.content;
  this.attrs = authenticatedAttributes;
  this.parseAttrs();
  this.addSignatureToken(tspTokenB);
};

Message.prototype.addSignatureToken = function addSignatureToken (tspTokenB) {
  if(!tspTokenB) {
    return;
  }
  const unauthenticatedAttributes = [
    tspTokenB && this.tspTokenAttr(tspTokenB)
  ].filter(attr => Boolean(attr));
  Object.assign(this.wrap.content.signerInfos[0], {unauthenticatedAttributes});
}

Message.prototype.digestAttr = function digestAttr(digestB) {
  return {
    type: "messageDigest",
    values: [dstszi2010.Data.encode(digestB, "der")]
  };
};

Message.prototype.tspAttr = function tspAttr(tspB) {
  return {
    type: "contentTimeStamp",
    values: [tspB]
  };
};

Message.prototype.tspTokenAttr = function tspAttr(tspB) {
  return {
    type: "timeStampToken",
    values: [tspB]
  };
};

Message.prototype.timeAttr = function timeAttr(time) {
  const date = time === undefined ? new Date(Date.now()) : new Date(1000 * time);

  const timeB = rfc3280.Time.encode({ type: "utcTime", value: date }, "der");
  return {
    type: "signingTime",
    values: [timeB]
  };
};

Message.prototype.contentType = function contentType(ct) {
  const obid = dstszi2010.ContentType.encode(ct, "der");
  return { type: "contentType", values: [obid] };
};

Message.prototype.certv2 = function certv2(cert, chash) {
  return {
    type: "signingCertificateV2",
    values: [certid.SigningCertificateV2.wrap(cert.ob, chash)]
  };
};

Message.prototype.parse = function parse(data) {
  const s_content_info = ContentInfo.decode(data, "der");

  this.wrap = s_content_info;
  this.type = s_content_info.contentType;
  this.info = s_content_info.content;

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
};

Message.prototype.mhash = function mhash(hash_f) {
  let dataToSign;
  if (this.attrs) {
    dataToSign = dstszi2010.Attributes.encode(this.attrs, "der");
  } else {
    dataToSign = this.info.contentInfo.content;
  }
  return hash_f(dataToSign);
};

function cap(name) {
  if(typeof name !== 'string') {
    return 'Unknown';
  }
  return name.substr(0, 1).toUpperCase()+name.substr(1);
}

Message.prototype.parseAttr = function parseAttrs({type, values}) {
  const methName = `parse${cap(type)}`;
  if (this[methName]) {
    return this[methName](values[0]);
  }
  return null;
}

Message.prototype.parseAttrs = function parseAttrs() {
  const pattrs = {};
  (this.attrs || []).forEach(el => {
    const parsed = this.parseAttr(el);
    if (parsed) {
      pattrs[el.type] = parsed;
    }
  });

   this.pattrs = pattrs;

  const puattrs = {};
  (this.uattrs || []).forEach(el => {
    const parsed = this.parseAttr(el);
    if (parsed) {
      puattrs[el.type] = parsed;
    }
  });
  this.puattrs = puattrs;
};

Message.prototype.parseMessageDigest = function parseMessageDigest(
  messageDigest
) {
  if (
    messageDigest[0] !== 0x04 ||
    messageDigest[1] !== messageDigest.length - 2
  ) {
    return undefined;
  }

  return messageDigest.slice(2);
};

Message.prototype.parseSigningTime = function parseSigningTime(stime) {
  return rfc3280.Time.decode(stime, "der").value;
};

Message.prototype.parseTimeStampToken = function parseTimeStampToken(token) {
  return new Message(token);
};

Message.prototype.parseContentTimeStamp = function parseContentTimeStamp(tsp) {
  return new Message(tsp);
}

Message.prototype.verifyAttrs = function verifyAttrs(hash_f, lookupCert, opts) {
  if (!this.attrs) {
    return true;
  }

  let ok;
  ok = this.verifyAttrDigest(this.pattrs.messageDigest, hash_f);
  ok = ok && this.verifySigningTime(this.pattrs.signingTime, lookupCert);
  if(opts.tsp) {
    ok = ok && this.verifyTimestampToken(this.pattrs.contentTime, hash_f, lookupCert, 'content');
  }
  if(opts.tsp === 'all') {
    ok = ok && this.verifyTimestampToken(this.puattrs.timeStampToken, hash_f, lookupCert, 'signature');
  }

  return ok;
};

function cmp(buf1, buf2) {
  let xor = 0;
  let idx = 0;
  for (idx = 0; (idx < buf1.length && idx < buf2.length); idx += 1) {
    xor |= buf1[idx] ^ buf2[idx];
  }
  return xor === 0;
}

Message.prototype.verifyAttrDigest = function verifyAttrDigest(dgst, hash_f) {
  if (!dgst) {
    return false;
  }
  const dataToSign = this.info.contentInfo.content;
  const hashbuf = hash_f(dataToSign);
  return cmp(dgst, hashbuf);
};

Message.prototype.verifySigningTime = function verifySigningTime(time, lookupCert) {
  if (!time) {
    return true;
  }
  const x509 = this.signer(lookupCert);
  return time >= x509.valid.from && time <= x509.valid.to;
};

Message.prototype.verifyTimestampToken = function verifyTimestampToken(msg, hash_f, lookupCert, imprintOf) {
  if(!msg) {
    return true;
  }
  const isSigned = msg.verify(hash_f, lookupCert);
  if(!isSigned) {
    return false;
  }

  const token = rfc3161.TSTInfo.decode(msg.info.contentInfo.content, 'der');
  if(token.messageImprint.hashAlgorithm.algorithm !== 'Gost34311') {
    return false;
  }
  return cmp(
    token.messageImprint.hashedMessage,
    hash_f({signature: this.signature(), content: hash_f(this.content())}[imprintOf])
  );
  return r;
}
 
Message.prototype.signature = function signature() {
  return this.info.signerInfos[0].encryptedDigest;
}

Message.prototype.content = function signature() {
  return this.info.contentInfo.content;
}

Message.prototype.signer = function signer(lookupCert) {
  const [certificate] = this.info.certificate || [];
  if(certificate) {
    return new Certificate(certificate);
  }
  const [{sid: {type, value}}] = this.info.signerInfos;
  if(type === 'issuerAndSerialNumber') {
    let pubkey = lookupCert(value);
    if (pubkey) {
      return pubkey;
    }
  }
  throw new ENOCERT();
};

Message.prototype.tokenTime = function tokenTime() {
  const msg = this.puattrs.timeStampToken;
  if(!msg) {
    return null;
  }
  const token = rfc3161.TSTInfo.decode(msg.info.contentInfo.content, 'der');
  return token.genTime;
}

Message.prototype.contentTime = function contentTime() {
  const msg = this.pattrs.contentTimeStamp;
  if(!msg) {
    return null;
  }
  const token = rfc3161.TSTInfo.decode(msg.info.contentInfo.content, 'der');
  return token.genTime;
}

Message.prototype.verify = function verify(hash_f, lookupCert, opts={}) {
  const hash = this.mhash(hash_f);

  if (!this.verifyAttrs(hash_f, lookupCert, opts)) {
    return false;
  }
  return this.signer(lookupCert).pubkey.verify(
    hash,
    this.signature(),
    "le"
  );
};

Message.prototype.decrypt = function decrypt(crypter, algo, lookupCert) {
  let pubkey;
  const ri = this.info.recipientInfos[0];
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
};

Message.prototype.as_asn1 = function as_asn1() {
  const buf = ContentInfo.encode(this.wrap, "der");
  return buf;
};

Message.prototype.as_transport = function as_transport(opts, addCert) {
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
};

module.exports = Message;
module.exports.ENOCERT = ENOCERT;
