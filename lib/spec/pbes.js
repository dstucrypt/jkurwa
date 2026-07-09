/*
 * PBES2 (Password-Based Encryption Scheme 2, RFC 2898/PKCS#5) container spec.
 *
 * ASN.1 models plus parse/serialize helpers for the encrypted private-key
 * container used by Ukrainian software. Unlike stock PKCS#5, the DSTU variant
 * derives the key with PBKDF2 over the GOST 34311 HMAC and encrypts with the
 * GOST 28147 cipher in CFB mode, carrying the S-box (dke) alongside the IV.
 */
import asn1 from "asn1.js";
import * as dstszi2010 from "./dstszi2010.js";

const CipherParams = dstszi2010.ContentEncryptionAlgorithmIdentifier;
const ContentInfo = dstszi2010.ContentInfo;

// Reference: https://www.rfc-editor.org/rfc/rfc2898

var OID = {
  "1 2 840 113549 1 5 13": "PBES2",
  "1 2 840 113549 1 5 12": "PBKDF2"
};

// PBKDF2 parameters: salt, iteration count (cycles), optional derived key
// length, and the PRF/hash algorithm (GOST 34311 HMAC for DSTU keys).
var PBKDF2_params = asn1.define("PBKDF2-params", function () {
  this.seq().obj(
    this.key("salt").octstr(),
    this.key("cycles").int(),
    this.key("keyLength").optional().int(),
    this.key("hash").use(CipherParams)
  );
});

var PBES2_params = asn1.define("PBES2-params", function () {
  this.seq().obj(
    this.key("keyDerivationFunc")
      .seq()
      .obj(this.key("id").objid(OID), this.key("params").use(PBKDF2_params)),
    this.key("encryptionScheme").use(CipherParams)
  );
});

var PBES2Algorithms = asn1.define("PBES2Algorithms", function () {
  this.seq().obj(
    this.key("algorithm").objid(OID),
    this.key("parameters").choice({
      null_: this.null_(),
      params: this.use(PBES2_params)
    })
  );
});

var PBES2 = asn1.define("StorePBES2", function () {
  this.seq().obj(
    this.key("contentEncryptionAlgorithm").use(PBES2Algorithms),
    this.key("encryptedContent").octstr()
  );
});

// Register PBES2 OIDs and params on the shared ContentInfo algorithm model so
// encryptedData ContentInfo values can resolve the PBES2 parameters.
Object.assign(ContentInfo.algoModel.IDS, OID);
Object.assign(ContentInfo.algoModel, { PBES2: PBES2_params });

/**
 * Decode a DER PBES2 container into a normalized descriptor.
 * @param {Buffer} data DER-encoded StorePBES2 structure.
 * @returns {Array<Object>} Single-element array with the parsed descriptor (see pbes2_parse_asn1).
 */
var pbes2_parse = function (data) {
  const obj = PBES2.decode(data, "der");
  return [pbes2_parse_asn1(obj)];
};

/**
 * Validate an already-decoded PBES2 structure and extract crypto parameters.
 * Enforces the DSTU profile: PBES2 + PBKDF2 + GOST 34311 HMAC + GOST 28147-CFB,
 * with fixed IV (8), S-box (64) and salt (32) lengths.
 * @param {Object} asn1 Decoded StorePBES2 object.
 * @returns {{format: string, iv: Buffer, sbox: Buffer, salt: Buffer, iters: number, body: Buffer}} Decryption parameters and ciphertext body.
 * @throws {Error} If any algorithm identifier or parameter length is unexpected.
 */
var pbes2_parse_asn1 = function (asn1) {
  var kdf, enc, params, iv, sbox, salt, iter;

  if (asn1.contentEncryptionAlgorithm.algorithm !== "PBES2") {
    throw new Error(asn1.contentEncryptionAlgorithm.algorithm);
  }
  if (asn1.contentEncryptionAlgorithm.parameters.type !== "params") {
    throw new Error(asn1.contentEncryptionAlgorithm.parameters.type);
  }
  kdf = asn1.contentEncryptionAlgorithm.parameters.value.keyDerivationFunc;
  if (kdf.id !== "PBKDF2") {
    throw new Error(kdf.id);
  }
  if (kdf.params.hash.algorithm !== "Gost34311-hmac") {
    throw new Error("Unknown cipher " + kdf.params.hash.algorithm);
  }
  enc = asn1.contentEncryptionAlgorithm.parameters.value.encryptionScheme;
  if (enc.algorithm !== "Gost28147-cfb") {
    throw new Error(enc.algorithm);
  }
  params = enc.parameters.value;
  if (params === null) {
    throw new Error("Encryption params not passed");
  }
  iv = params.iv;
  sbox = params.dke; // GOST 28147 S-box (substitution table)
  salt = kdf.params.salt;
  iter = kdf.params.cycles;

  if (iv.length !== 8 || sbox.length !== 64 || salt.length !== 32) {
    throw new Error(
      "IV len: " +
        iv.length +
        ", S-BOX len: " +
        sbox.length +
        ", SALT len: " +
        salt.length
    );
  }
  return {
    format: "PBES2",
    iv: iv,
    sbox: sbox,
    salt: salt,
    iters: iter.toNumber(),
    body: asn1.encryptedContent
  };
};

/**
 * Serialize a store descriptor back into a DER PBES2 container.
 * The iteration count is fixed at 10000 and the DSTU algorithm identifiers
 * are hard-coded to match the profile enforced by pbes2_parse_asn1.
 * @param {{salt: Buffer, iv: Buffer, sbox: Buffer, body: Buffer}} store Salt, IV, S-box and encrypted body.
 * @returns {Buffer} DER-encoded StorePBES2 structure.
 */
var pbes2_serialize = function (store) {
  return PBES2.encode(
    {
      contentEncryptionAlgorithm: {
        algorithm: "PBES2",
        parameters: {
          type: "params",
          value: {
            keyDerivationFunc: {
              id: "PBKDF2",
              params: {
                salt: store.salt,
                cycles: 10000,
                hash: {
                  algorithm: "Gost34311-hmac",
                  parameters: {
                    type: "null_",
                    value: null
                  }
                }
              }
            },
            encryptionScheme: {
              algorithm: "Gost28147-cfb",
              parameters: {
                type: "params",
                value: {
                  iv: store.iv,
                  dke: store.sbox
                }
              }
            }
          }
        }
      },
      encryptedContent: store.body
    },
    "der"
  );
};

export default PBES2;
export {
  OID,
  pbes2_parse,
  pbes2_serialize as enc_serialize,
  pbes2_parse_asn1 as obj_parse
};
