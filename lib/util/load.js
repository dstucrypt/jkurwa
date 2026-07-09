/*
 * Key and certificate loader.
 *
 * Normalizes the many ways callers can supply keys/certs (already-parsed
 * objects, PEM strings, file paths, or raw buffers) into a flat list of
 * {priv} / {cert} entries. Supports Java KeyStore (JKS) containers and
 * DSTU protected private-key stores, transparently unwrapping the MeDoc
 * "garbage" file-header prefix when present.
 */
import fs from "fs";
import jksreader from "jksreader";

import complain from "./complain.js";
import Priv from "../models/Priv.js";
import Certificate from "../models/Certificate.js";

/**
 * Decode a JKS store's key material and append its keys and certs to ret.
 * @param {Array} ret - accumulator list of {priv}/{cert} entries.
 * @param {{material:Array}} store - parsed JKS store.
 * @param {string|Buffer} password - password protecting the JKS entries.
 * @returns {Array} the same ret list with entries appended.
 */
function loadJks(ret, store, password) {
  if (!password) {
    throw new Error("JKS file format requires password to be opened");
  }
  for (let part of store.material) {
    const buf = jksreader.decode(part.key, password.toString());
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

/**
 * Load private keys and certificates from mixed keyinfo sources into a flat list.
 * @param {Object} keyinfo - key/cert sources (priv, cert, privPem, certPem, keyBuffers, certBuffers, privPath, certPath, password).
 * @param {*} [algo] - optional cipher algorithm hint for protected stores.
 * @returns {Array.<{priv?:*,cert?:*}>} loaded key/cert entries.
 */
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
    // MeDoc key files begin with 0x51 ('Q') plus a 6-byte prefix; strip it.
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
    store.certs.forEach(cert =>
      ret.push({ cert: Certificate.from_asn1(cert) })
    );
  });

  certBuffers.forEach(cert => ret.push({ cert: Certificate.from_pem(cert) }));
  return ret;
}

export default load;
export { loadJks };
