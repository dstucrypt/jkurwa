const Message = require("../models/Message");
const Certificate = require("../models/Certificate");

const rand = require("../rand");
const filterRole = require("../util/role");
const transport = require("../util/transport");
const load = require("../util/load");
const { EOLD } = require("../util/complain");
const { useContentTsp, useSignatureTsp } = require("../util/tsp");
const tspService = require("../services/tsp");
const ocspService = require("../services/ocsp");

class ENOKEY extends Error {}

const OP_TO_KEY_BIT = {
  sign: 0x80,
  encrypt: 0x08
};
const filterComplete = function filterComplete(ob) {
  return ob.cert && ob.priv;
};

const filterUsage = function filterUsage(op, ob) {
  const data = ob.cert.extension.keyUsage;
  const bits = data[data.length - 1];
  return bits & OP_TO_KEY_BIT[op];
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
  static load = load;
  constructor(opts = {}) {
    this.pubIdx = {};
    this.cas = {};
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
    Object.keys(this.cas).forEach(idx => {
      const calist = this.cas[idx];
      for (let ca of calist) {
        const rdn = Certificate.formatRDN(
          ca.tbsCertificate.serialNumber,
          ca.tbsCertificate.issuer.value
        );
        certs[rdn] = ca;
      }
    });
    this.certs = certs;
  }

  loadCAs(buffer) {
    const msg = new Message(buffer);
    for (let certOb of msg.info.certificate) {
      certOb.trusted = true;
      let query = Certificate.formatDN(certOb.tbsCertificate.subject.value);
      this.cas[query] = (this.cas[query] || []).concat([certOb]);
    }
    this._keys();
    this.hasCA = true;
    Object.freeze(this);
  }

  lookupCA(query, keyId) {
    for (let ca of this.cas[query] || []) {
      let cert = new Certificate(ca);
      cert.trusted = true;
      if (!keyId || cert.subjectKeyId.equals(keyId)) {
        return cert;
      }
    }
    return null;
  }

  lookupCert(helpCerts, query) {
    const rdnQuery = Certificate.formatRDN(
      query.serialNumber,
      query.issuer.value
    );
    for (let cert of helpCerts) {
      if (cert.rdnSerial() === rdnQuery) {
        return cert;
      }
    }
    let ret = this.certs[rdnQuery];
    if (ret && ret.format !== "x509") {
      ret = new Certificate(ret);
      ret.trusted = Boolean(ret.trusted);
    }
    return ret || null;
  }

  async lookupOCSP(lookup, query) {
    const rdnKey = Certificate.formatRDN(
      query.serialNumber,
      query.issuer.value
    );
    const cert = lookup(query);
    if (!cert) {
      return { isOk: false, unknown: true };
    }
    try {
      return await ocspService.lookup(
        cert,
        rand(Buffer.alloc(20)),
        this.query,
        this.lookupCA.bind(this),
        this.algo.hash
      );
    } catch (e) {
      return { isOk: false };
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

  async sign(data, role, cert, opts) {
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
    const help_cert = [];
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
          signed = msg.verify(this.algo.hash, lookup, opts);
          x = msg.signer(lookup);
          if (!filterUsage("sign", { cert: x })) {
            throw Message.ENOCERT();
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
          cert: {
            subject: x.subject,
            issuer: x.issuer,
            extension: x.extension,
            valid: x.valid
          },
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
          entry.cert.verified = x.verify(
            { time },
            { Dstu4145le: this.algo.hash },
            this.lookupCA.bind(this)
          );
          if (!entry.cert.verified) {
            info.pipe.push({ broken_cert: true, error: "ESIGN" });
            break;
          }
        }
        help_cert.push(x);

        if (opts.ocsp) {
          entry.ocsp = await Promise.all(
            msg.signedWithCerts.map(query => this.lookupOCSP(lookup, query))
          );
          if (
            !entry.ocsp.every(ocsp => ocsp.statusOk) &&
            opts.ocsp === "strict"
          ) {
            info.pipe.push({ broken_cert: true, error: "EOCSP" });
            break;
          }
        }

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
module.exports.EOLD = EOLD;
