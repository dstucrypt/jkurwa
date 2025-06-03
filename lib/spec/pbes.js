import asn1 from 'asn1.js';
import * as dstszi2010 from './dstszi2010.js';
import * as rfc3280 from './rfc3280.js';


const CipherParams = dstszi2010.ContentEncryptionAlgorithmIdentifier;
const ContentInfo = dstszi2010.ContentInfo;

// Reference: https://www.rfc-editor.org/rfc/rfc2898

var OID = {
    '1 2 840 113549 1 5 13': "PBES2",
    "1 2 840 113549 1 5 12": "PBKDF2",
};

var PBKDF2_params = asn1.define('PBKDF2-params', function () {
  this.seq().obj(
      this.key("salt").octstr(),
      this.key("cycles").int(),
      this.key("keyLength").optional().int(),
      this.key("hash").use(CipherParams)
  );
});

var PBES2_params = asn1.define('PBES2-params', function () {
  this.seq().obj(
    this.key("keyDerivationFunc").seq().obj(
      this.key("id").objid(OID),
      this.key('params').use(PBKDF2_params),
      ),
    this.key("encryptionScheme").use(CipherParams)
  );
});

var PBES2Algorithms = asn1.define('PBES2Algorithms', function () {
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


Object.assign(ContentInfo.algoModel.IDS, OID);
Object.assign(ContentInfo.algoModel, { 'PBES2' : PBES2_params });


var pbes2_parse = function (data) {
    const obj = PBES2.decode(data, 'der');
    return [pbes2_parse_asn1(obj)];
}

var pbes2_parse_asn1 = function (asn1) {
    var kdf, enc, params, iv, sbox, salt, iter;

    if (asn1.contentEncryptionAlgorithm.algorithm !== 'PBES2') {
        throw new Error(asn1.contentEncryptionAlgorithm.algorithm);
    }
    if (asn1.contentEncryptionAlgorithm.parameters.type !== 'params') {
      throw new Error(asn1.contentEncryptionAlgorithm.parameters.type);
    }
    kdf = asn1.contentEncryptionAlgorithm.parameters.value.keyDerivationFunc;
    if (kdf.id !== 'PBKDF2') {
        throw new Error(kdf.id);
    }
    if (kdf.params.hash.algorithm !== 'Gost34311-hmac') {
        throw new Error("Unknown cipher " + kdf.params.hash.algorithm);
    }
    enc = asn1.contentEncryptionAlgorithm.parameters.value.encryptionScheme;
    if (enc.algorithm !== 'Gost28147-cfb') {
        throw new Error(enc.algorithm);
    }
    params = enc.parameters.value;
    if (params === null) {
        throw new Error("Encryption params not passed");
    }
    iv = params.iv;
    sbox = params.dke;
    salt = kdf.params.salt;
    iter = kdf.params.cycles;

    if ((iv.length !== 8) || (sbox.length !== 64) || (salt.length !== 32)) {
        throw new Error("IV len: " + iv.length + ", S-BOX len: " + sbox.length + ", SALT len: " + salt.length);
    }
    return {
        "format": "PBES2",
        "iv": iv,
        "sbox": sbox,
        "salt": salt,
        "iters": iter.toNumber(),
        "body": asn1.encryptedContent,
    };
};


var pbes2_serialize = function(store) {
    return PBES2.encode({
      contentEncryptionAlgorithm: {
        algorithm: 'PBES2',
        parameters: {
          type: 'params',
          value: {
            keyDerivationFunc: {
              id: "PBKDF2",
              params: {
                salt: store.salt,
                cycles: 10000,
                hash: {
                  algorithm: 'Gost34311-hmac',
                  parameters: {
                    type: 'null_',
                    value: null,
                  },
                },
              },
            },
            encryptionScheme: {
              algorithm: 'Gost28147-cfb',
              parameters: {
                type: 'params',
                value: {
                  iv: store.iv,
                  dke: store.sbox,
                }
              }
            },
          }
        },
      },
      encryptedContent: store.body,
    }, 'der');
}

export default PBES2;
export { OID, pbes2_parse as pbes2_parse, pbes2_serialize as enc_serialize, pbes2_parse_asn1 as obj_parse };
