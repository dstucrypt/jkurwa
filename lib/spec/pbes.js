import asn1 from "asn1.js";
import * as dstszi2010 from "./dstszi2010.js";
import * as rfc3280 from "./rfc3280.js";

const CipherParams = dstszi2010.ContentEncryptionAlgorithmIdentifier;
const ContentInfo = dstszi2010.ContentInfo;

// Reference: https://www.rfc-editor.org/rfc/rfc2898

var OID = {
  "1 2 840 113549 1 5 13": "PBES2",
  "1 2 840 113549 1 5 12": "PBKDF2"
};

var PBKDF2_params = asn1.define("PBKDF2-params", function() {
  this.seq().obj(
    this.key("salt").octstr(),
    this.key("cycles").int(),
    this.key("keyLength")
      .optional()
      .int(),
    this.key("hash").use(CipherParams)
  );
});

var PBES2_params = asn1.define("PBES2-params", function() {
  this.seq().obj(
    this.key("keyDerivationFunc")
      .seq()
      .obj(this.key("id").objid(OID), this.key("params").use(PBKDF2_params)),
    this.key("encryptionScheme").use(CipherParams)
  );
});

var PBES2Algorithms = asn1.define("PBES2Algorithms", function() {
  this.seq().obj(
    this.key("algorithm").objid(OID),
    this.key("parameters").choice({
      null_: this.null_(),
      params: this.use(PBES2_params)
    })
  );
});

var PBES2 = asn1.define("StorePBES2", function() {
  this.seq().obj(
    this.key("contentEncryptionAlgorithm").use(PBES2Algorithms),
    this.key("encryptedContent").octstr()
  );
});

Object.assign(ContentInfo.algoModel.IDS, OID);
Object.assign(ContentInfo.algoModel, { PBES2: PBES2_params });

var pbes2_parse = function(data) {
  const obj = PBES2.decode(data, "der");
  return [pbes2_parse_asn1(obj)];
};

// PBES2 wraps two unrelated password-based profiles in the wild:
//
//   * the legacy GOST profile - PBKDF2-HMAC(Gost34311) + Gost28147-CFB,
//     identified by an 8-byte IV and a 64-byte DKE s-box;
//   * the DSTU profile used by Kupyna/Kalyna key containers -
//     PBKDF2-HMAC(Dstu7564mac-256) + Dstu7624-CBC with a 32-byte IV.
//
// The KDF hash algorithm is the discriminator: it determines which encryption
// scheme and parameter shape must follow.  The pair is validated together, not
// field by field - a store claiming Gost34311-hmac with Dstu7624-CBC is not a
// variant we support, and guessing at it would produce a key that decrypts to
// garbage long after the container was accepted.
var PBES2_PROFILES = {
  "Gost34311-hmac": {
    algorithm: "Gost28147-cfb",
    ivLength: 8,
    readParams(params) {
      if (params.dke.length !== 64) {
        throw new Error("S-BOX len: " + params.dke.length);
      }
      return { iv: params.iv, sbox: params.dke };
    }
  },
  "Dstu7564mac-256": {
    algorithm: "Dstu7624cbc-256",
    ivLength: 32,
    readParams(params) {
      return { iv: params.iv };
    }
  }
};

var pbes2_parse_asn1 = function(asn1) {
  var kdf, enc, params, salt, iter;

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

  salt = kdf.params.salt;
  iter = kdf.params.cycles;
  if (salt.length !== 32) {
    throw new Error("SALT len: " + salt.length);
  }

  var profile = PBES2_PROFILES[kdf.params.hash.algorithm];
  if (!profile) {
    throw new Error("Unknown cipher " + kdf.params.hash.algorithm);
  }

  enc = asn1.contentEncryptionAlgorithm.parameters.value.encryptionScheme;
  if (enc.algorithm !== profile.algorithm) {
    throw new Error(
      "Cipher " +
        enc.algorithm +
        " does not match KDF " +
        kdf.params.hash.algorithm
    );
  }
  params = enc.parameters.value;
  if (params === null) {
    throw new Error("Encryption params not passed");
  }
  if (params.iv.length !== profile.ivLength) {
    throw new Error("IV len: " + params.iv.length);
  }

  const { iv, sbox } = profile.readParams(params);

  return {
    format: "PBES2",
    iv: iv,
    sbox: sbox,
    salt: salt,
    iters: iter.toNumber(),
    body: asn1.encryptedContent,
    // The consumers (custom algo.storeload implementations) dispatch on these
    // two names, so surface the actual algorithms instead of assuming GOST.
    kdf: kdf.params.hash.algorithm,
    enc: enc.algorithm
  };
};

var pbes2_serialize = function(store) {
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

PBES2.obj_parse = pbes2_parse_asn1;
PBES2.pbes2_parse = pbes2_parse;

export default PBES2;
export {
  OID,
  pbes2_parse,
  pbes2_serialize as enc_serialize,
  pbes2_parse_asn1 as obj_parse
};
