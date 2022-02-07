const Message = require("../models/Message");
const Certificate = require("../models/Certificate");
const CertificateRef = require("../models/CertificateRef");

const rand = require("../rand");
const filterRole = require("../util/role");
const transport = require("../util/transport");
const load = require("../util/load");
const { EOLD } = require("../util/complain");
const { useContentTsp, useSignatureTsp } = require("../util/tsp");
const tspService = require("../services/tsp");
const ocspService = require("../services/ocsp");
const cmpService = require("../services/cmp");

const CERT_CACHE_CUTOFF_MS = 15 * 60 * 1000;

class ENOKEY extends Error {}

const filterComplete = function filterComplete(ob) {
  return ob.cert && ob.priv;
};

const filterUsage = function filterUsage(op, ob) {
  return ob.cert.canUseFor(op);
};

const filterRid = function filterRid(rid, ob) {
  if (!rid) {
    return true;
  }

  if (rid.type === "issuerAndSerialNumber") {
    const rdnQuery = Certificate.formatRDN(
      rid.value.serialNumber,
      rid.value.issuer.value
    );
    return ob.cert.rdnSerial() === rdnQuery;
  }
  return false;
};

class Box {
  constructor(opts = {}) {
    this.pubIdx = {};
    this.cas = {};
    this.casRDN = {};
    this.certsRDN = {};
    this.verifiedCache = {};
    this.certCacheCutoff = CERT_CACHE_CUTOFF_MS;
    this.algo = opts.algo || {};

    if (opts.keys) {
      this.loadMaterial(opts.keys);
    }
    if (opts.casBuffer) {
      this.loadCAs(opts.casBuffer);
    }

    this._keys();
    this.query = opts.query || null;
  }

  get ocspCtx() {
    return {
      query: this.query,
      lookupCA: this.lookupCA.bind(this),
      hashFn: this.algo.hash
    };
  }

  loadMaterial(info) {
    for (let datum of info) {
      for (let key of Box.load(datum, this.algo)) {
        this.add(key, this.algo);
      }
    }
  }

  load(keyinfo) {
    for (let key of Box.load(keyinfo, this.algo)) {
      this.add(key, this.algo);
    }
    this._keys();
  }

  async loadCertsCmp(url) {
    const keyids = this.keys
      .filter(info => info.priv)
      .map(info => info.priv.pub().keyid(this.algo));
    const [key0, key1] = keyids;

    const certificates = await cmpService.lookup(keyids, url, this.query);
    let numberAdded = 0;
    for(let cert of certificates) {
      if (key0 && cert.extension.subjectKeyIdentifier.equals(key0)) {
        this.add({ cert });
        numberAdded += 1;
      }
      if (key1 && cert.extension.subjectKeyIdentifier.equals(key1)) {
        this.add({ cert });
        numberAdded += 1;
      }

    }
    return numberAdded;
  }

  async findCertsCmp(urlsHint) {
    let steps = [];
    if (urlsHint && urlsHint.length) {
      steps = [urlsHint];
    } else {
      steps = this.getUniqueOCSPUrls()
        .map(url=> [url.replace(/ocsp/, 'cmp')]);
    }
    const loadOne = (url)=> {
      return this.loadCertsCmp(url).catch(e=> 0);
    }
    for (let step of steps) {
      let results = await Promise.all(step.map(loadOne));
      let nonZero = results.find(number=> number > 0);
      if (nonZero) {
        return nonZero;
      }
    }
    return 0;
  }

  getUniqueOCSPUrls() {
    let ret = [];
    if (this._cachedOcspUrls) {
      return this._cachedOcspUrls;
    }
    this._cachedOcspUrls = ret;
    Object.keys(this.cas).forEach(idx => {
      const calist = this.cas[idx];
      for (let ca of calist) {
        const cert = new Certificate(ca);
        if (!cert.extension.authorityInfoAccess || cert.extension.authorityInfoAccess.id !== 'ocsp') {
          continue;
        }
        const url = cert.extension.authorityInfoAccess.link;
        if (url && !ret.includes(url) ) {
          ret.push(url);
        }
      }
    });
    return ret;
  }

  _keys() {
    const certs = {};
    this.keys = Object.keys(this.pubIdx).map(idx => {
      const ret = this.pubIdx[idx];
      if (!ret.cert) {
        return ret;
      }

      const rdn = ret.cert.rdnSerial();
      certs[rdn] = ret.cert;
      return ret;
    });
    this.certsRDN = certs;
  }

  _indexCAs() {
    Object.keys(this.cas).forEach(idx => {
      const calist = this.cas[idx];
      for (let ca of calist) {
        const rdn = Certificate.formatRDN(
          ca.tbsCertificate.serialNumber,
          ca.tbsCertificate.issuer.value
        );
        this.casRDN[rdn] = ca;
      }
    });
  }

  loadCAs(buffer) {
    const msg = new Message(buffer);
    for (let certOb of msg.info.certificate) {
      certOb.trusted = true;
      let query = Certificate.formatDN(certOb.tbsCertificate.subject.value);
      this.cas[query] = (this.cas[query] || []).concat([certOb]);
    }
    this._indexCAs();
    this._keys();
    this.hasCA = true;
  }

  lookupCA(query, keyId) {
    for (let ca of this.cas[query] || []) {
      let cert = new Certificate(ca);
      cert.trusted = true;
      if (!keyId || cert.extension.subjectKeyIdentifier.equals(keyId)) {
        return cert;
      }
    }
    return null;
  }

  lookupByKeyId(helpCerts, keyId) {
    for (let cert of helpCerts) {
      if (cert.extension.subjectKeyIdentifier.equals(keyId)) {
        return cert;
      }
    }
    throw new Message.ENOCERT();
  }

  lookupCert(helpCerts, query) {
    if (query.keyid) {
      return this.lookupByKeyId(helpCerts, query.keyid);
    }
    const rdnQuery = Certificate.formatRDN(
      query.serialNumber,
      query.issuer.value
    );
    for (let cert of helpCerts) {
      if (cert.rdnSerial() === rdnQuery) {
        return cert;
      }
    }
    let ret = this.certsRDN[rdnQuery] || this.casRDN[rdnQuery];
    if (ret && ret.format !== "x509") {
      ret = new Certificate(ret);
      ret.trusted = Boolean(ret.trusted);
    }
    return ret || null;
  }

  lookupIssuedBy(query) {
    for (let list of Object.values(this.cas)) {
      for (let cert of list) {
        if (Certificate.formatDN(cert.tbsCertificate.issuer.value) === query) {
          return new Certificate(cert);
        }
      }
    }
  }

  verifyCert(cert, time, usage) {
    const lastViable = Date.now() - this.certCacheCutoff;
    const sid = cert.extension.subjectKeyIdentifier;
    const sidHex = sid ? sid.toString("hex") : null;

    let cachedRes =
      sidHex && this.verifiedCache.hasOwnProperty(sidHex)
        ? this.verifiedCache[sidHex]
        : null;

    if (cachedRes && cachedRes.ctime < lastViable) {
      cachedRes = null;
      delete this.verifiedCache[sidHex];
    }

    if (cachedRes && !cachedRes.ret) {
      return false;
    }

    if (cachedRes && cachedRes.ret === true) {
      return (
        (usage ? cert.canUseFor(usage) : true) && cert.verifyTime(Number(time))
      );
    }

    const ret = cert.verify(
      { time, usage },
      { Dstu4145le: this.algo.hash },
      this.lookupCA.bind(this)
    );
    this.verifiedCache[sidHex] = { ret, ctime: Date.now() };
    return ret;
  }

  lookupCertOrSibling(lookup, query) {
    let cert = lookup(query);
    if (!cert) {
      // Opportunistic OCSP certificate discovery.
      // If we don't already have certificate mentioned in query,
      // there is a good chance we at least have another certificate issued
      // by same CA.
      // For OCSP we only need a url, issuer name, authority key id and serial,
      // so combined together sibling certificate and serial of the one we need
      // would not only check certificate status, but also download certificate
      // itself.
      const issuer = this.lookupCA(Certificate.formatDN(query.issuer.value));
      cert = issuer && this.lookupIssuedBy(issuer.subjectDN());
    }
    return cert;
  }

  async lookupOCSP(lookup, query, msg) {
    const cert = this.lookupCertOrSibling(lookup, query);
    if (!cert) {
      return { statusOk: false, unknown: true };
    }
    const ocspCtx = this.ocspCtx;
    let response = msg.puattrs.revocationValues.find(iterResponse =>
      iterResponse.matches(cert, query.serialNumber, ocspCtx)
    );
    let nonce;
    const isOcspStamp = Boolean(response);
    if (response) {
      nonce = null;
    } else {
      nonce = rand(Buffer.alloc(20));
      try {
        response = await ocspService.lookup(
          cert,
          query.serialNumber,
          nonce,
          ocspCtx
        );
      } catch (e) {}
    }

    if (!response) {
      return { statusOk: false, unknown: true };
    }

    try {
      return response.verify(
        ocspCtx,
        cert,
        query.serialNumber,
        nonce,
        isOcspStamp
      );
    } catch (e) {
      return { statusOk: false };
    }
  }

  add({ cert, priv }) {
    if (!cert && !priv) {
      return;
    }
    const pub = cert ? cert.pubkey : priv.pub();
    const idx = pub.point.toString();
    const container = this.pubIdx[idx] || {};
    container.priv = container.priv || priv;
    container.cert = container.cert || cert;
    this.pubIdx[idx] = container;
  }

  async sign(data, role, unusedCert, opts) {
    const key = this.keyFor("sign", role);
    const dataHash = this.algo.hash(data);
    let tspB;
    if (useContentTsp(opts.tsp)) {
      tspB = await tspService.getStamp(key.cert, dataHash, this.query);
    }
    const message = new Message({
      type: "signedData",
      cert: key.cert,
      data: opts.detached ? null : data,
      dataHash,
      signer: key.priv,
      hash: this.algo.hash,
      tspB,
      signTime: opts.time
    });
    if (useSignatureTsp(opts.tsp)) {
      const signHash = this.algo.hash(message.signature);
      tspB = await tspService.getStamp(key.cert, signHash, this.query);
      message.addSignatureToken(tspB);
    }

    if (opts.includeChain) {
      const chain = key.cert.getCompleteChain(this.lookupCA.bind(this));
      message.addCertRefs(
        chain.map(cert => CertificateRef.fromCert(cert, this.algo.hash))
      );
      if (opts.includeChain !== "ref") {
        message.addCertValues(chain);
      }
    }

    if (opts.ocsp) {
      let ocspResponses = await Promise.all(
        message.signedWithCerts.map(async query => {
          const lookup = this.lookupCert.bind(this, [key.cert]);
          const cert = this.lookupCertOrSibling(lookup, query);
          if (!cert) {
            return null;
          }
          const nonce = rand(Buffer.alloc(20));
          const response = await ocspService.lookup(
            cert,
            query.serialNumber || cert.serial,
            nonce,
            this.ocspCtx
          );
          const info = response.verify(
            this.ocspCtx,
            cert,
            query.serialNumber,
            nonce,
            false
          );
          if (!info.statusOk) {
            return null;
          }
          return response;
        })
      );
      ocspResponses = ocspResponses.filter(iter => iter);
      message.addOcspHashes(
        ocspResponses.map(iter => [iter.makeRef(this.ocspCtx)])
      );
      if (opts.ocsp !== "ref") {
        message.addOcspResponses(ocspResponses);
      }
    }
    return message;
  }

  encrypt(data, role, forCert, opts) {
    if (forCert === undefined) {
      throw new Error("No recipient specified for encryption");
    }
    const key = this.keyFor("encrypt", role);
    return new Message({
      type: "envelopedData",
      cert: key.cert,
      toCert: forCert,
      data,
      crypter: key.priv,
      algo: this.algo
    });
  }

  keyFor(op, role, query) {
    const [firstKey] = this.keys
      .filter(filterComplete)
      .filter(filterRid.bind(null, query))
      .filter(filterUsage.bind(null, op))
      .filter(filterRole.bind(null, role));
    if (!firstKey || !firstKey.priv) {
      throw new ENOKEY(
        `No key-certificate pair found for given op ${op} and role ${role}`,
        { op, role }
      );
    }
    return firstKey;
  }

  async pipe(data, commands, opts, cb) {
    let [cmd, ...restCommands] = commands;
    if (!cmd) {
      return data;
    }
    if (typeof cmd === "string") {
      cmd = { op: cmd };
    }
    if (cmd.op === undefined) {
      throw new Error("Broken pipeline element", cmd);
    }
    let cert = cmd.forCert;
    if (typeof cert === "string") {
      cert = Certificate.from_pem(cert);
    }
    const msg = await this[cmd.op](data, cmd.role, cert, cmd);
    return this.pipe(
      cmd.tax ? msg.as_transport(opts, cmd.addCert) : msg.as_asn1(),
      restCommands,
      opts
    );
  }

  async unwrap(data, content, opts = {}) {
    let msg;
    let x;
    const info = { pipe: [] };
    let tr;
    let signed;
    let key;
    let help_cert = [];
    const lookup = query => this.lookupCert(help_cert, query);
    while (data && data.length) {
      try {
        tr = transport.decode(data);
      } catch (e) {
        tr = null;
      }
      if (tr) {
        if (tr.header) {
          info.pipe.push({ transport: true, headers: tr.header });
        }
        msg = tr.docs.shift();
        while (msg.type === "CERTCRYPT") {
          help_cert.push(Certificate.from_asn1(msg.contents));
          msg = tr.docs.shift();
        }
        if (msg.type.substr(3) === "_CRYPT" || msg.type.substr(3) === "_SIGN") {
          data = msg.contents;
        }

        if (msg.type.substr(0, 3) === "QLB" && tr.docs.length > 0) {
          content = tr.docs.shift().contents;
        }
        if (msg.type === "DOCUMENT" && msg.encoding === "PACKED_XML_DOCUMENT") {
          data = msg.contents;
          continue;
        }
      }
      try {
        msg = new Message(data);
      } catch (e) {
        if (tr === null) {
          break;
        }
        throw e;
      }
      if (msg.type === "signedData") {
        if (msg.info.contentInfo.content === undefined) {
          if (content === undefined) {
            info.pipe.push({ error: "ENODATA" });
            break;
          }
          msg.info.contentInfo.content = content;
        }

        try {
          help_cert.push(msg.signer(lookup));
        } catch (e) {
          if (!(e instanceof Message.ENOCERT)) throw e;
        }

        let ocspResult;
        if (opts.ocsp) {
          ocspResult = await Promise.all(
            msg.signedWithCerts.map(query =>
              this.lookupOCSP(lookup, query, msg)
            )
          );

          if (
            opts.ocsp === "lax"
              ? !ocspResult.every(ocsp => ocsp.statusOk || !ocsp.requestOK)
              : !ocspResult.every(ocsp => ocsp.statusOk)
          ) {
            info.pipe.push({ broken_cert: true, error: "EOCSP" });
            break;
          }
          let discoveredCerts = ocspResult
            .filter(ocsp => ocsp.statusOk && ocsp.cert)
            .map(ocsp => new Certificate(ocsp.cert));
          help_cert = [...help_cert, ...discoveredCerts];
        }

        try {
          signed = msg.verify(
            this.algo.hash,
            lookup,
            this.lookupCA.bind(this),
            opts
          );
          x = msg.signer(lookup);
          if (!x.canUseFor("sign")) {
            throw new Message.ENOCERT();
          }
        } catch (e) {
          if (!(e instanceof Message.ENOCERT)) throw e;
          info.pipe.push({ signed: true, error: "ENOCERT" });
          break;
        }
        if (signed !== true) {
          info.pipe.push({ broken_sign: true, error: "ESIGN" });
          break;
        }
        data = msg.info.contentInfo.content;
        let entry = {
          signed,
          ocsp: ocspResult,
          cert: x.as_dict(),
          signingTime: msg.pattrs.signingTime,
          contentTime: (useContentTsp(opts.tsp) && msg.contentTime) || null,
          tokenTime: (useSignatureTsp(opts.tsp) && msg.tokenTime) || null
        };
        let time =
          entry.tokenTime ||
          entry.contentTime ||
          entry.signingTime ||
          Date.now();
        if (this.hasCA) {
          entry.cert.verified = this.verifyCert(x, time, "sign");
          if (!entry.cert.verified) {
            info.pipe.push({ broken_cert: true, error: "ESIGN" });
            break;
          }
        }
        help_cert.push(x);

        info.pipe.push(entry);
      }
      if (msg.type === "envelopedData") {
        try {
          key = this.keyFor("encrypt", null, msg.receiverKey);
        } catch (e) {
          if (!(e instanceof ENOKEY)) throw e;

          info.pipe.push({ enc: true, error: "ENOKEY" });
          break;
        }
        info.pipe.push({
          enc: true
        });
        try {
          data = msg.decrypt(key.priv, this.algo, lookup);
        } catch (e) {
          if (!(e instanceof Message.ENOCERT)) throw e;

          info.pipe.push({ enc: true, error: "ENOCERT" });
          break;
        }
      }
    }
    info.content = data;
    if (info.pipe.length && info.pipe[info.pipe.length - 1].error) {
      info.error = info.pipe[info.pipe.length - 1].error;
    }
    return info;
  }
}

module.exports = Box;
module.exports.load = load;
module.exports.EOLD = EOLD;
