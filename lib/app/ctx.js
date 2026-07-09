/*
 * High-level application context for the DSTU 4145 crypto library.
 *
 * `Box` is the top-level facade that ties together the caller's private keys,
 * their certificates, the trusted CA list and the hash/cipher `algo` bundle,
 * then exposes the end-to-end pipelines: sign / encrypt (produce a Message)
 * and verify / decrypt (consume one via `unwrap`/`pipe`). It also handles
 * certificate lookup and validation, opportunistic certificate discovery,
 * OCSP revocation checking and TSP time-stamping, and per-message hash
 * selection between legacy GOST 34.311 and Kupyna (DSTU 7564).
 */
import Message from "../models/Message.js";
import Certificate from "../models/Certificate.js";
import CertificateRef from "../models/CertificateRef.js";

import rand from "../rand.js";
import filterRole from "../util/role.js";
import transport from "../util/transport.js";
import load from "../util/load.js";
import {
  hashAlgo,
  hashMaps,
  digestForSig,
  digestForChoice
} from "../util/hashes.js";
import { EOLD } from "../util/complain.js";
import { useContentTsp, useSignatureTsp } from "../util/tsp.js";
import * as tspService from "../services/tsp.js";
import * as ocspService from "../services/ocsp.js";
import * as cmpService from "../services/cmp.js";

// How long a positive certificate-verification result stays cached before it
// is re-checked (chain/time validation is expensive, so results are memoized).
const CERT_CACHE_CUTOFF_MS = 15 * 60 * 1000;

// Thrown when no key/certificate pair satisfies the requested op/role/recipient.
class ENOKEY extends Error {}

// Thrown when sign() is asked for a hash that is unknown or has no
// implementation available (e.g. a typo in the `hash`/`hashMethod` value).
class EHASH extends Error {}

// Keep only entries that have BOTH a private key and its certificate; signing
// and encryption need the cert (for the recipient/signer info), not just a key.
const filterComplete = function filterComplete(ob) {
  return ob.cert && ob.priv;
};

// Keep only certificates whose key-usage/extended-key-usage permits `op`
// ("sign" or "encrypt"), so we never sign with an encryption-only cert etc.
const filterUsage = function filterUsage(op, ob) {
  return ob.cert.canUseFor(op);
};

// Match a specific recipient identifier (RID) from a CMS message. Used when a
// caller wants the key for a particular certificate rather than any usable one.
const filterRid = function filterRid(rid, ob) {
  if (!rid) {
    return true;
  }

  if (rid.type === "issuerAndSerialNumber") {
    // Compare the entry's cert against the "issuer + serial" string form of
    // the RID; keyid-based RIDs are handled elsewhere, so they never match here.
    const rdnQuery = Certificate.formatRDN(
      rid.value.serialNumber,
      rid.value.issuer.value
    );
    return ob.cert.rdnSerial() === rdnQuery;
  }
  return false;
};

/**
 * Facade over key material, certificates, CAs and the crypto algo bundle.
 * Exposes the sign/encrypt producers and the verify/decrypt `unwrap`/`pipe`
 * consumers, plus certificate lookup, validation, OCSP and TSP helpers.
 */
class Box {
  /**
   * @param {Object} [opts]
   * @param {Object} [opts.algo] Hash/cipher implementation bundle (`{ hash, ... }`).
   * @param {string} [opts.hashMethod] Default signing hash: "gost" | "kupyna" | "auto".
   * @param {Array} [opts.keys] Key material to load immediately (see Box.load).
   * @param {Buffer} [opts.casBuffer] Serialized trusted-CA store to load immediately.
   * @param {Function} [opts.query] Async transport used for OCSP/TSP/CMP network calls.
   */
  constructor(opts = {}) {
    this.cas = {};        // trusted CA certs indexed by subject DN string
    this.casRDN = {};     // trusted CA certs indexed by "issuer + serial" (RDN)
    this.certsRDN = {};   // loaded leaf certs indexed by "issuer + serial" (RDN)
    this.certsById = {};  // loaded leaf certs indexed by hex key id
    this.keysById = {};   // private keys indexed by hex key id
    this.verifiedCache = {}; // memoized verifyCert() results keyed by subject key id
    this.certCacheCutoff = CERT_CACHE_CUTOFF_MS;
    this.algo = opts.algo || {};
    // Default hash for signing: "gost" | "kupyna" | "auto" (or unset = auto).
    // Overridable per call via sign() opts.hash.
    this.hashMethod = opts.hashMethod || null;
    this.keys = [];

    if (opts.keys) {
      this.loadMaterial(opts.keys);
    }
    if (opts.casBuffer) {
      this.loadCAs(opts.casBuffer);
    }

    this.query = opts.query || null;
  }

  /**
   * Lookup maps of hash functions keyed by DSTU algorithm OID name. Rebuilt
   * only when `this.algo` changes (identity check), cheap otherwise.
   * @returns {Object} `{ byDigest, bySig, ... }` hash-function lookup tables.
   */
  get hashMaps() {
    if (this._hashMapsFor !== this.algo) {
      this._hashMaps = hashMaps(this.algo || {});
      this._hashMapsFor = this.algo;
    }
    return this._hashMaps;
  }

  /**
   * Pick the hash function matching a message's declared digestAlgorithm so
   * Kupyna- and GOST-signed messages verify with the correct digest.
   * @param {Message} msg Message being verified.
   * @returns {Function} Hash function, or the primary `algo.hash` fallback.
   */
  hashForMessage(msg) {
    return this.hashMaps.byDigest[msg.digestAlgo] || this.algo.hash;
  }

  /**
   * Pick the hash function implied by a certificate's signatureAlgorithm, so
   * signing with a Kupyna key/cert uses Kupyna and a legacy GOST cert uses
   * GOST 34.311 — without the caller specifying anything. Falls back to the
   * primary `algo.hash` when the matching hash was not supplied.
   * @param {Certificate} cert Signing certificate.
   * @returns {Function} Hash function to sign with.
   */
  hashForCert(cert) {
    const digest = digestForSig(cert && cert.signatureAlgorithm);
    return this.hashMaps.byDigest[digest] || this.algo.hash;
  }

  /**
   * Resolve the hash to sign with. A forced choice (per-call `hash`, else the
   * Box `hashMethod`) wins; "auto"/unset falls back to per-certificate
   * selection. `choice` may be "gost"/"kupyna"/size alias/OID name/hash fn.
   * @param {Certificate} cert Signing certificate (used for the auto fallback).
   * @param {(string|Function)} [choice] Forced hash; undefined uses `hashMethod`.
   * @returns {Function} Hash function to sign with.
   * @throws {EHASH} If a named hash is requested that is unknown/unavailable.
   */
  resolveSignHash(cert, choice) {
    const forced = choice === undefined ? this.hashMethod : choice;
    if (typeof forced === "function") {
      return forced;
    }
    const digest = digestForChoice(forced);
    if (!digest) {
      return this.hashForCert(cert);
    }
    const hash = this.hashMaps.byDigest[digest];
    if (!hash) {
      throw new EHASH(
        `Unknown or unavailable hash "${forced}". Use "gost", "kupyna", ` +
          `"kupyna-384", "kupyna-512", "auto", or pass a tagged hash function.`
      );
    }
    return hash;
  }

  /**
   * Shared context bundle passed to OCSP request/verify helpers: transport,
   * CA lookup, the request-signing hash and the verification hash maps.
   * @returns {Object}
   */
  get ocspCtx() {
    return {
      query: this.query,
      lookupCA: this.lookupCA.bind(this),
      hashFn: this.algo.hash,
      hashVerify: this.hashMaps.bySig
    };
  }

  /**
   * Load several pieces of key material (keys/certs), then rebuild the key index.
   * @param {Array} info Array of loadable key/cert descriptors.
   * @returns {void}
   */
  loadMaterial(info) {
    for (let datum of info) {
      for (let part of Box.load(datum, this.algo)) {
        this.add(part, this.algo);
      }
    }
    this._indexKeys();
  }

  /**
   * Load a single piece of key material (key and/or cert), then rebuild the index.
   * @param {*} keyinfo A loadable key/cert descriptor.
   * @returns {void}
   */
  load(keyinfo) {
    for (let part of Box.load(keyinfo, this.algo)) {
      this.add(part, this.algo);
    }
    this._indexKeys();
  }

  /**
   * Fetch our own certificates from a CMP server by our private keys' key ids
   * and add any that are returned.
   * @param {string} url CMP endpoint URL.
   * @returns {Promise<number>} Count of fetched certs that matched a held key.
   */
  async loadCertsCmp(url) {
    const keyids = this.keys
      .filter(info => info.priv)
      .map(info => info.priv.pub().keyid(this.algo));
    const [key0, key1] = keyids;

    const certificates = await cmpService.lookup(keyids, url, this.query);
    let numberAdded = 0;
    for (let cert of certificates) {
      const keyid = cert.extension.subjectKeyIdentifier.toString("hex");
      // Only count certs we actually have the matching private key for; other
      // returned certs are still added, but don't count toward "found mine".
      if (this.keysById[keyid]) {
        numberAdded += 1;
      }
      this.add({ cert });
    }
    this._indexKeys();
    return numberAdded;
  }

  /**
   * Try to locate our certificates via CMP, deriving candidate CMP URLs from
   * the CAs' OCSP URLs when none are supplied. Stops at the first URL that
   * yields at least one matching cert.
   * @param {string[]} [urlsHint] Explicit CMP URLs to try first.
   * @returns {Promise<number>} Count from the first successful lookup, else 0.
   */
  async findCertsCmp(urlsHint) {
    let steps = [];
    if (urlsHint && urlsHint.length) {
      steps = [urlsHint];
    } else {
      // No hint: guess CMP endpoints by swapping "ocsp" -> "cmp" in CA OCSP URLs.
      steps = this.getUniqueOCSPUrls().map(url => [url.replace(/ocsp/, "cmp")]);
    }
    const loadOne = url => {
      // Network/lookup failures are swallowed to 0 so one bad URL doesn't abort.
      return this.loadCertsCmp(url).catch(e => 0);
    };
    for (let step of steps) {
      let results = await Promise.all(step.map(loadOne));
      let nonZero = results.find(number => number > 0);
      if (nonZero) {
        return nonZero;
      }
    }
    return 0;
  }

  /**
   * Collect the distinct OCSP responder URLs advertised by the loaded CAs.
   * Result is memoized on first call.
   * @returns {string[]} Unique OCSP URLs.
   */
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
        if (
          !cert.extension.authorityInfoAccess ||
          cert.extension.authorityInfoAccess.id !== "ocsp"
        ) {
          continue;
        }
        const url = cert.extension.authorityInfoAccess.link;
        if (url && !ret.includes(url)) {
          ret.push(url);
        }
      }
    });
    return ret;
  }

  // Rebuild the flat `keys` list, pairing each private key with the cert that
  // shares its key id (or null). This is the list keyFor()/filters operate on.
  _indexKeys() {
    this.keys = Object.entries(this.keysById).map(([keyid, priv]) => ({
      priv,
      cert: this.certsById[keyid] || null,
      keyid
    }));
  }

  // Build the RDN ("issuer + serial") -> CA cert index used by lookupCert.
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

  /**
   * Load a serialized store of trusted CA certificates and index them by
   * subject DN and RDN. Marks each as trusted and flips the `hasCA` flag that
   * enables certificate-chain validation during unwrap.
   * @param {Buffer} buffer Serialized CMS message containing the CA certs.
   * @returns {void}
   */
  loadCAs(buffer) {
    const msg = new Message(buffer);
    for (let certOb of msg.info.certificate) {
      certOb.trusted = true;
      let query = Certificate.formatDN(certOb.tbsCertificate.subject.value);
      // Several CAs can share a subject DN (e.g. re-issued roots): keep a list.
      this.cas[query] = (this.cas[query] || []).concat([certOb]);
    }
    this._indexCAs();
    this._indexKeys();
    this.hasCA = true;
  }

  /**
   * Find a trusted CA certificate by subject DN, optionally requiring a
   * specific subject key id (to disambiguate re-issued CAs sharing a DN).
   * @param {string} query Subject DN string.
   * @param {Buffer} [keyId] Required subject key identifier.
   * @returns {Certificate|null} The matching trusted CA cert, or null.
   */
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

  /**
   * Find a certificate in a candidate list by its subject key identifier.
   * @param {Certificate[]} helpCerts Candidate certificates.
   * @param {Buffer} keyId Subject key identifier to match.
   * @returns {Certificate}
   * @throws {Message.ENOCERT} If no candidate matches.
   */
  lookupByKeyId(helpCerts, keyId) {
    for (let cert of helpCerts) {
      if (cert.extension.subjectKeyIdentifier.equals(keyId)) {
        return cert;
      }
    }
    throw new Message.ENOCERT();
  }

  /**
   * Resolve the certificate referenced by a signer/recipient query. Prefers a
   * key-id match, else matches "issuer + serial" against the candidate list and
   * then the loaded leaf/CA indexes.
   * @param {Certificate[]} helpCerts Certificates carried in the message itself.
   * @param {Object} query Signer info: either `{ keyid }` or `{ serialNumber, issuer }`.
   * @returns {Certificate|null} Resolved certificate, or null if not found.
   */
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
    // Fall back to loaded leaf certs, then trusted CAs. Raw ASN.1 records are
    // wrapped into Certificate objects, preserving their trusted flag.
    let ret = this.certsRDN[rdnQuery] || this.casRDN[rdnQuery];
    if (ret && ret.format !== "x509") {
      ret = new Certificate(ret);
      ret.trusted = Boolean(ret.trusted);
    }
    return ret || null;
  }

  /**
   * Find any trusted CA certificate issued by the given issuer DN.
   * @param {string} query Issuer DN string.
   * @returns {Certificate|undefined} A matching CA cert, or undefined.
   */
  lookupIssuedBy(query) {
    for (let list of Object.values(this.cas)) {
      for (let cert of list) {
        if (Certificate.formatDN(cert.tbsCertificate.issuer.value) === query) {
          return new Certificate(cert);
        }
      }
    }
  }

  /**
   * Verify a certificate's chain against the loaded CAs, with the result cached
   * per subject key id. Usage and validity-at-time are re-checked on cache hits
   * (they depend on the call's `usage`/`time`, not just the cached chain result).
   * @param {Certificate} cert Certificate to validate.
   * @param {(number|Date)} time Point in time the cert must be valid at.
   * @param {string} [usage] Required key usage ("sign"/"encrypt").
   * @returns {boolean} True if the cert is trusted, valid at `time` and usable.
   */
  verifyCert(cert, time, usage) {
    const lastViable = Date.now() - this.certCacheCutoff;
    const sid = cert.extension.subjectKeyIdentifier;
    const sidHex = sid ? sid.toString("hex") : null;

    let cachedRes =
      sidHex && this.verifiedCache.hasOwnProperty(sidHex)
        ? this.verifiedCache[sidHex]
        : null;

    // Drop cache entries older than the cutoff so revocation/expiry is picked up.
    if (cachedRes && cachedRes.ctime < lastViable) {
      cachedRes = null;
      delete this.verifiedCache[sidHex];
    }

    // A cached negative chain result is final; a bad chain can't become good.
    if (cachedRes && !cachedRes.ret) {
      return false;
    }

    // Cached positive chain result: still re-check usage and time-validity,
    // since those vary per call and aren't captured by the cached boolean.
    if (cachedRes && cachedRes.ret === true) {
      return (
        (usage ? cert.canUseFor(usage) : true) && cert.verifyTime(Number(time))
      );
    }

    const ret = cert.verify(
      { time, usage },
      this.hashMaps.bySig,
      this.lookupCA.bind(this)
    );
    this.verifiedCache[sidHex] = { ret, ctime: Date.now() };
    return ret;
  }

  /**
   * Resolve the queried certificate, or failing that any sibling cert from the
   * same CA — enough to build an OCSP request that also returns the real cert.
   * @param {Function} lookup Certificate resolver, e.g. bound `lookupCert`.
   * @param {Object} query Signer info `{ serialNumber, issuer, ... }`.
   * @returns {Certificate|undefined} The exact cert, a sibling, or undefined.
   */
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

  /**
   * Determine the revocation status of the cert named by `query`. Prefers an
   * OCSP response already embedded in the message (an "OCSP stamp"); otherwise
   * makes a live, nonce-protected OCSP request. Network errors are swallowed.
   * @param {Function} lookup Certificate resolver.
   * @param {Object} query Signer info identifying the cert to check.
   * @param {Message} msg Signed message (source of any embedded OCSP responses).
   * @returns {Promise<Object>} Verification result, `{ statusOk, ... }`.
   */
  async lookupOCSP(lookup, query, msg) {
    const cert = this.lookupCertOrSibling(lookup, query);
    if (!cert) {
      return { statusOk: false, unknown: true };
    }
    const ocspCtx = this.ocspCtx;
    // Prefer an OCSP response bundled in the message (offline/archival case).
    let response = msg.puattrs.revocationValues.find(iterResponse =>
      iterResponse.matches(cert, query.serialNumber, ocspCtx)
    );
    let nonce;
    // Embedded responses were produced earlier, so no nonce is expected/checked.
    const isOcspStamp = Boolean(response);
    if (response) {
      nonce = null;
    } else {
      // No embedded response: query the responder live, binding a fresh nonce.
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

  /**
   * Index a certificate and/or private key by its public-key id (and RDN for
   * certs). Key and cert with the same key id later pair up in `_indexKeys`.
   * @param {Object} entry
   * @param {Certificate} [entry.cert] Certificate to index.
   * @param {Priv} [entry.priv] Private key to index.
   * @returns {void}
   */
  add({ cert, priv }) {
    if (!cert && !priv) {
      return;
    }
    // Both key and cert are keyed by the same public-key id so they can be paired.
    const pub = cert ? cert.pubkey : priv.pub();
    const keyid = pub.keyid(this.algo).toString("hex");
    if (cert) {
      this.certsById[keyid] = cert;
      this.certsRDN[cert.rdnSerial()] = cert;
    }
    if (priv) {
      this.keysById[keyid] = priv;
    }
  }

  /**
   * Produce a CMS signedData message over `data`, optionally with content/
   * signature time-stamps (TSP), the full certificate chain, and OCSP proofs.
   * @param {Buffer} data Content to sign.
   * @param {string} [role] Role filter used to pick the signing key/cert.
   * @param {*} unusedCert Ignored (kept for pipe()'s uniform call signature).
   * @param {Object} opts
   * @param {(string|Function)} [opts.hash] Forced signing hash (else auto per cert).
   * @param {boolean} [opts.detached] If true, omit the content from the message.
   * @param {*} [opts.tsp] TSP mode controlling content/signature time-stamping.
   * @param {(boolean|string)} [opts.includeChain] Embed cert chain; "ref" = hashes only.
   * @param {(boolean|string)} [opts.ocsp] Embed OCSP proofs; "ref" = hashes only.
   * @param {*} [opts.time] Signing time to record.
   * @returns {Promise<Message>} The assembled signedData message.
   */
  async sign(data, role, unusedCert, opts) {
    const key = this.keyFor("sign", role);
    // Hash selection: a forced choice (opts.hash, else Box hashMethod) wins,
    // otherwise it is picked from the signing certificate — Kupyna cert ->
    // Kupyna, legacy GOST cert -> GOST 34.311.
    const hashFn = this.resolveSignHash(key.cert, opts && opts.hash);
    const dataHash = hashFn(data);
    const digestAlgo = hashAlgo(hashFn);
    let tspB;
    // Content TSP: time-stamp the data hash and embed it before signing.
    if (useContentTsp(opts.tsp)) {
      tspB = await tspService.getStamp(
        key.cert,
        dataHash,
        this.query,
        digestAlgo
      );
    }
    const message = new Message({
      type: "signedData",
      cert: key.cert,
      data: opts.detached ? null : data,
      dataHash,
      signer: key.priv,
      hash: hashFn,
      tspB,
      signTime: opts.time
    });
    // Signature TSP: time-stamp the finished signature and attach it as an
    // unsigned attribute (proves the signature existed at the stamped time).
    if (useSignatureTsp(opts.tsp)) {
      const signHash = hashFn(message.signature);
      tspB = await tspService.getStamp(
        key.cert,
        signHash,
        this.query,
        digestAlgo
      );
      message.addSignatureToken(tspB);
    }

    if (opts.includeChain) {
      const chain = key.cert.getCompleteChain(this.lookupCA.bind(this));
      message.addCertRefs(
        chain.map(cert => CertificateRef.fromCert(cert, hashFn))
      );
      if (opts.includeChain !== "ref") {
        message.addCertValues(chain);
      }
    }

    // Embed OCSP proof-of-validity for each signer cert so the signature can be
    // validated offline later. Certs that can't be resolved or aren't "good"
    // are dropped rather than failing the whole sign.
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
      // "ref" embeds only response hashes; otherwise embed the full responses.
      if (opts.ocsp !== "ref") {
        message.addOcspResponses(ocspResponses);
      }
    }
    return message;
  }

  /**
   * Produce a CMS envelopedData message encrypting `data` for `forCert`.
   * @param {Buffer} data Plaintext to encrypt.
   * @param {string} [role] Role filter used to pick the sender's key/cert.
   * @param {Certificate} forCert Recipient certificate (required).
   * @param {Object} [opts] Unused; kept for pipe()'s uniform signature.
   * @returns {Message} The assembled envelopedData message.
   * @throws {Error} If no recipient certificate is given.
   */
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

  /**
   * Select the first held key/cert pair usable for the given operation, role
   * and (optional) recipient identifier.
   * @param {string} op Operation the cert must permit ("sign"/"encrypt").
   * @param {string} [role] Role the cert must satisfy (see util/role).
   * @param {Object} [query] Recipient identifier to match a specific cert.
   * @returns {{priv: Priv, cert: Certificate, keyid: string}} The chosen pair.
   * @throws {ENOKEY} If no pair matches all filters.
   */
  keyFor(op, role, query) {
    // Successive filters narrow candidates: must be complete (key+cert), match
    // the requested recipient, be permitted for `op`, and satisfy `role`.
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

  /**
   * Run `data` through a sequence of sign/encrypt commands, feeding each step's
   * serialized output into the next. Recurses over the command list.
   * @param {Buffer} data Initial content.
   * @param {Array<(string|Object)>} commands Steps, each `"sign"`/`"encrypt"` or
   *   `{ op, role, forCert, tax, addCert, ... }`.
   * @param {Object} opts Options threaded to transport serialization.
   * @param {Function} [cb] Unused.
   * @returns {Promise<Buffer>} Final serialized message after all steps.
   */
  async pipe(data, commands, opts, cb) {
    let [cmd, ...restCommands] = commands;
    if (!cmd) {
      return data;
    }
    // Allow a bare op name as shorthand for `{ op }`.
    if (typeof cmd === "string") {
      cmd = { op: cmd };
    }
    if (cmd.op === undefined) {
      throw new Error("Broken pipeline element", cmd);
    }
    let cert = cmd.forCert;
    // A PEM-string recipient is parsed to a Certificate before use.
    if (typeof cert === "string") {
      cert = Certificate.from_pem(cert);
    }
    const msg = await this[cmd.op](data, cmd.role, cert, cmd);
    // `tax` selects the transport envelope (with optional cert), else plain ASN.1;
    // the serialized result becomes the input to the next pipeline step.
    return this.pipe(
      cmd.tax ? msg.as_transport(opts, cmd.addCert) : msg.as_asn1(),
      restCommands,
      opts
    );
  }

  /**
   * Peel apart a (possibly multi-layer) signed/encrypted message, verifying
   * signatures and decrypting envelopes layer by layer until plain content
   * remains. Each layer appends a status entry to `info.pipe`; the first error
   * stops the loop and is surfaced as `info.error`.
   * @param {Buffer} data The wrapped message bytes.
   * @param {Buffer} [content] Detached content for a signature that omits it.
   * @param {Object} [opts]
   * @param {(boolean|string)} [opts.ocsp] Enforce OCSP; "lax" tolerates unreachable responders.
   * @param {*} [opts.tsp] Whether to trust/report content and signature time-stamps.
   * @returns {Promise<Object>} `{ pipe, content, error? }` describing each layer and the payload.
   */
  async unwrap(data, content, opts = {}) {
    let msg;
    let x;
    const info = { pipe: [] };
    let tr;
    let signed;
    let key;
    // Certs discovered while unwrapping (from transport, signers, OCSP) feed the
    // resolver so inner layers can find issuer/signer certs carried by outer ones.
    let help_cert = [];
    const lookup = query => this.lookupCert(help_cert, query);
    while (data && data.length) {
      // Each pass first tries to strip a proprietary transport envelope; if that
      // fails the bytes are treated directly as a CMS Message.
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
        // Leading CERTCRYPT docs carry certs to help resolve the real payload.
        while (msg.type === "CERTCRYPT") {
          help_cert.push(Certificate.from_asn1(msg.contents));
          msg = tr.docs.shift();
        }
        if (msg.type.substr(3) === "_CRYPT" || msg.type.substr(3) === "_SIGN") {
          data = msg.contents;
        }

        // QLB transports carry the detached content as a second document.
        if (msg.type.substr(0, 3) === "QLB" && tr.docs.length > 0) {
          content = tr.docs.shift().contents;
        }
        // A packed-XML document wrapper: unwrap once more and restart the loop.
        if (msg.type === "DOCUMENT" && msg.encoding === "PACKED_XML_DOCUMENT") {
          data = msg.contents;
          continue;
        }
      }
      try {
        msg = new Message(data);
      } catch (e) {
        // If there was no transport frame either, the bytes are the final
        // plaintext, not a message — stop unwrapping. Otherwise it's a real error.
        if (tr === null) {
          break;
        }
        throw e;
      }
      if (msg.type === "signedData") {
        // Detached signature: splice in the externally supplied content, or bail.
        if (msg.info.contentInfo.content === undefined) {
          if (content === undefined) {
            info.pipe.push({ error: "ENODATA" });
            break;
          }
          msg.info.contentInfo.content = content;
        }

        // Register the signer's own cert (if resolvable) so it can validate
        // itself and help resolve subsequent layers; missing cert is tolerated
        // here and re-checked below.
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

          // Strict mode requires every cert to be OCSP-good; "lax" also accepts
          // certs whose responder simply couldn't be reached (requestOK false).
          if (
            opts.ocsp === "lax"
              ? !ocspResult.every(ocsp => ocsp.statusOk || !ocsp.requestOK)
              : !ocspResult.every(ocsp => ocsp.statusOk)
          ) {
            info.pipe.push({ broken_cert: true, error: "EOCSP" });
            break;
          }
          // OCSP siblings often return the queried cert itself; fold those in.
          let discoveredCerts = ocspResult
            .filter(ocsp => ocsp.statusOk && ocsp.cert)
            .map(ocsp => new Certificate(ocsp.cert));
          help_cert = [...help_cert, ...discoveredCerts];
        }

        try {
          // Verify using the hash the message declares, then re-fetch the signer
          // cert and reject it if it isn't actually allowed to sign.
          signed = msg.verify(
            this.hashForMessage(msg),
            lookup,
            this.lookupCA.bind(this),
            opts
          );
          x = msg.signer(lookup);
          if (!x.canUseFor("sign")) {
            throw new Message.ENOCERT();
          }
        } catch (e) {
          // Only a missing/unusable signer cert is a soft failure; other errors
          // (e.g. malformed message) propagate.
          if (!(e instanceof Message.ENOCERT)) throw e;
          info.pipe.push({ signed: true, error: "ENOCERT" });
          break;
        }
        if (signed !== true) {
          info.pipe.push({ broken_sign: true, error: "ESIGN" });
          break;
        }
        // Signature is good: the signed content becomes the next layer's input.
        data = msg.info.contentInfo.content;
        let entry = {
          signed,
          ocsp: ocspResult,
          cert: x.as_dict(),
          signingTime: msg.pattrs.signingTime,
          contentTime: (useContentTsp(opts.tsp) && msg.contentTime) || null,
          tokenTime: (useSignatureTsp(opts.tsp) && msg.tokenTime) || null
        };
        // Validate the cert as of the most trustworthy timestamp available,
        // preferring a signature token, then content stamp, then claimed signing
        // time, and finally now.
        let time =
          entry.tokenTime ||
          entry.contentTime ||
          entry.signingTime ||
          Date.now();
        // Chain validation only runs when a CA store is loaded.
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
        // Need our own private key matching the message's recipient info.
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
          // Decrypt; the plaintext becomes the next layer's input.
          data = msg.decrypt(key.priv, this.algo, lookup);
        } catch (e) {
          if (!(e instanceof Message.ENOCERT)) throw e;

          info.pipe.push({ enc: true, error: "ENOCERT" });
          break;
        }
      }
    }
    info.content = data;
    // Surface the last layer's error (if any) as the overall unwrap error.
    if (info.pipe.length && info.pipe[info.pipe.length - 1].error) {
      info.error = info.pipe[info.pipe.length - 1].error;
    }
    return info;
  }
}

export default Box;
Box.load = load;
Box.EOLD = EOLD;
Box.EHASH = EHASH;
export { load, EOLD, EHASH };
