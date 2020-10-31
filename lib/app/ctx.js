const jksreader = require("jksreader");

const fs = require("fs");
const Priv = require("../models/Priv");
const Message = require("../models/Message");
const Certificate = require("../models/Certificate");

const transport = require("../util/transport");
const tspService = require("../services/tsp");

class ENOKEY extends Error {}
class EOLD extends Error {}

function complain(msg) {
  if (!EOLD.silent) {
    console.error(msg, new EOLD());
  }
}

const loadJks = function loadJks(ret, store, password) {
  if (!password) {
    throw new Error("JKS file format requires password to be opened");
  }
  let idx;
  let jidx;
  for (idx = 0; idx < store.material.length; idx++) {
    const part = store.material[idx];
    const buf = jksreader.decode(part.key, password);
    if (!buf) {
      throw new Error("Cant load key from store, check password");
    }
    const rawStore = Priv.from_asn1(buf, true);
    for (jidx = 0; jidx < part.certs.length; jidx++) {
      ret({ cert: Certificate.from_pem(part.certs[jidx]) });
    }
    for (jidx = 0; jidx < rawStore.keys.length; jidx++) {
      ret({ priv: rawStore.keys[jidx] });
    }
  }
};

function load(ret, algo, keyinfo) {
  if (
    (keyinfo.priv && keyinfo.priv.type === "Priv") ||
    (keyinfo.cert && keyinfo.cert.format === "x509")
  ) {
    ret({ priv: keyinfo.priv });
    ret({ cert: keyinfo.cert });
  }
  if (keyinfo.privPem) {
    ret({ priv: Priv.from_pem(keyinfo.privPem) });
  }
  if (keyinfo.certPem) {
    ret({ cert: Certificate.from_pem(keyinfo.certPem) });
  }

  let keyBuffers = keyinfo.keyBuffers || [];
  if (keyinfo.privPath) {
    complain("keyinfo.privPath is deprecated and would be removed");
    let keyPaths =
      typeof keyinfo.privPath === "string"
        ? [keyinfo.privPath]
        : keyinfo.privPath || [];

    keyBuffers = [
      ...keyBuffers,
      ...keyPaths.map(path => fs.readFileSync(path))
    ];
  }

  keyBuffers.forEach(buf => {
    // detect garbage in file header (meeedok)
    const content = buf[0] === 0x51 ? buf.slice(6) : buf;
    const jksStore = jksreader.parse(content);
    if (jksStore) {
      loadJks(ret, jksStore, keyinfo.password);
      return;
    }
    let store;
    try {
      store = Priv.from_protected(content, keyinfo.password, algo);
    } catch (ignore) {
      throw new Error("Cant load key from store");
    }
    store.keys.forEach(priv => ret({ priv }));
  });

  let certBuffers = keyinfo.certBuffers || [];
  if (keyinfo.certPath) {
    complain("keyinfo.certPath is deprecated and would be removed");
    let certPaths =
      typeof keyinfo.certPath === "string"
        ? [keyinfo.certPath]
        : keyinfo.certPath || [];
    certBuffers = [
      ...certBuffers,
      ...certPaths.map(path => Certificate.from_pem(fs.readFileSync(path)))
    ];
  }
  certBuffers.forEach(cert => ret({ cert }));
}

const useContentTsp = value => ["all", "content"].includes(value);
const useSignatureTsp = value => ["all", "signature"].includes(value);
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

const DRFO_FORMAT = [
  /^[0-9]{10}$/, // standard DRFO code ten digits;
  /^[0-9]{9}$/, // id card (new passport) number nine digits used in lieu of DRFO code for religious people.
  /^[a-zA-Z]{2}[0-9]{6}$/ // old passport number AA123456 used in lieu of DRFO code for religious people.
];
function isNaturalPerson(code) {
  let idx;
  let format;
  for (idx = 0; idx < DRFO_FORMAT.length; idx++) {
    format = DRFO_FORMAT[idx];
    if (code.match(format)) {
      return true;
    }
  }
  return false;
}

/* This code checks if certificate is suitable for given role.
 *
 * Possible values are:
 *
 * personal - certificate belongs to natural person and has no record
 *            of any corporate entity;
 * fop (fizychna osoba pidpryjemets) - certificate belongs to natural person
 *            registered as private entrepreneur, technically this means
 *            that personal code (10, 9 or 8 digit DRFO) matches corporate code (EDRPOU);
 * director - certificate either belongs to FOP or natural person that
 *            can sign on behalf of corporate entity, technicall this means
 *            that corporate code either matches drfo or drfo code is present,
 *            but corporate code does not belong to natural person;
 * stamp - certificate belongs to corporate entity itself, not natural person;
 * other - personal code is present but does not match corporate code (relaxed version of director);
 * exact personal code to match. should be 10, 9 or 8 characters long (see above)  */
const filterRole = function filerRole(role, ob) {
  if (!ob.cert) {
    return false;
  }
  const { ipn } = ob.cert.extension;
  if (!role) {
    return true;
  }
  if (role === "personal") {
    return Boolean(!ipn.EDRPOU && ipn.DRFO);
  }
  if (role === "fop") {
    return ipn.EDRPOU === ipn.DRFO;
  }
  if (role === "director") {
    return (
      ipn.EDRPOU === ipn.DRFO || (ipn.DRFO && !isNaturalPerson(ipn.EDRPOU))
    );
  }
  if (role === "stamp") {
    return Boolean(ipn.EDRPOU && !ipn.DRFO);
  }
  if (role === "other") {
    return Boolean(ipn.DRFO && ipn.EDRPOU !== ipn.DRFO);
  }

  return ipn.DRFO === role;
};

class Box {
  constructor(opts = {}) {
    opts = opts || {};

    this.pubIdx = {};

    if (opts.keys) {
      opts.keys.forEach(load.bind(null, this.add.bind(this), opts.algo));
    }

    this._keys();
    this.algo = opts.algo || {};
    this.query = opts.query || null;
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
    this.certs = certs;
  }

  lookupCert(add, query) {
    const rdnQuery = Certificate.formatRDN(
      query.serialNumber,
      query.issuer.value
    );
    for (let idx = 0; idx < add.length; idx++) {
      if (add[idx].rdnSerial() === rdnQuery) {
        return add[idx];
      }
    }
    return this.certs[rdnQuery] || null;
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

  load(keyinfo) {
    load(this.add.bind(this), this.algo, keyinfo);
    this._keys();
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
      const signHash = this.algo.hash(message.signature());
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

  keyFor(op, role) {
    const [firstKey] = this.keys
      .filter(filterComplete)
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

  unwrap(data, content, opts = {}) {
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
          x = msg.signer(lookup);
        } catch (e) {
          if (!(e instanceof Message.ENOCERT)) throw e;
          info.pipe.push({ signed: true, error: "ENOCERT" });
          break;
        }

        signed = msg.verify(this.algo.hash, lookup, opts);
        if (signed !== true) {
          info.pipe.push({ broken_sign: true, error: "ESIGN" });
          break;
        }
        data = msg.info.contentInfo.content;
        info.pipe.push({
          signed,
          cert: {
            subject: x.subject,
            issuer: x.issuer,
            extension: x.extension,
            valid: x.valid
          },
          signingTime: msg.pattrs.signingTime,
          contentTime: (useContentTsp(opts.tsp) && msg.contentTime()) || null,
          tokenTime: (useSignatureTsp(opts.tsp) && msg.tokenTime()) || null
        });
      }
      if (msg.type === "envelopedData") {
        try {
          key = this.keyFor("encrypt");
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
