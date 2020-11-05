const fs = require("fs");
const jksreader = require("jksreader");

const complain = require("./complain");
const Priv = require("../models/Priv");
const Certificate = require("../models/Certificate");

function loadJks(ret, store, password) {
  if (!password) {
    throw new Error("JKS file format requires password to be opened");
  }
  for (let part of store.material) {
    const buf = jksreader.decode(part.key, password);
    if (!buf) {
      throw new Error("Cant load key from store, check password");
    }
    const rawStore = Priv.from_asn1(buf, true);
    for (let cert of part.certs) {
      ret.push({ cert: Certificate.from_pem(cert) });
    }
    for (let priv of rawStore.keys) {
      ret.push({ priv });
    }
  }
  return ret;
}

function load(keyinfo, algo) {
  let ret = [];
  if (keyinfo.priv && keyinfo.priv.type === "Priv") {
    ret.push({ priv: keyinfo.priv });
  }
  if (keyinfo.cert && keyinfo.cert.format === "x509") {
    ret.push({ cert: keyinfo.cert });
  }
  if (keyinfo.privPem) {
    ret.push({ priv: Priv.from_pem(keyinfo.privPem) });
  }
  if (keyinfo.certPem) {
    ret.push({ cert: Certificate.from_pem(keyinfo.certPem) });
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
  let certBuffers = keyinfo.certBuffers || [];
  if (keyinfo.certPath) {
    complain("keyinfo.certPath is deprecated and would be removed");
    let certPaths =
      typeof keyinfo.certPath === "string"
        ? [keyinfo.certPath]
        : keyinfo.certPath || [];
    certBuffers = [
      ...certBuffers,
      ...certPaths.map(path => fs.readFileSync(path))
    ];
  }

  keyBuffers.forEach(buf => {
    // detect garbage in file header (meeedok)
    const content = buf[0] === 0x51 ? buf.slice(6) : buf;
    const jksStore = jksreader.parse(content);
    if (jksStore) {
      return loadJks(ret, jksStore, keyinfo.password);
    }
    let store;
    try {
      store = Priv.from_protected(content, keyinfo.password, algo);
    } catch (ignore) {
      throw new Error("Cant load key from store");
    }
    store.keys.forEach(priv => ret.push({ priv }));
  });

  certBuffers.forEach(cert => ret.push({ cert: Certificate.from_pem(cert) }));
  return ret;
}
module.exports = load;
module.exports.loadJks = loadJks;
