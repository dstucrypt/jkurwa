'use strict';

var asn1 = require('asn1.js'),
    dstszi2010 = require('./dstszi2010.js'),
    rfc3280 = require('./rfc3280'),
    CipherParams = dstszi2010.ContentEncryptionAlgorithmIdentifier;


var OID = {
    '1 2 840 113549 1 5 13': "PBES2",
    "1 2 840 113549 1 5 12": "PBKDF2",
};

var PBES2 = asn1.define("StorePBES2", function () {
    this.seq().obj(
        this.key("head").seq().obj(
            this.key("id").objid(OID),
            this.key("pbes2").seq().obj(
                this.key("keyDerivationFunc").seq().obj(
                    this.key("id").objid(OID),
                    this.key('params').seq().obj(
                        this.key("salt").octstr(),
                        this.key("cycles").int(),
                        this.key("keyLength").optional().int(),
                        this.key("hash").use(CipherParams)
                    )
                ),
                this.key("encryptionScheme").use(CipherParams)
            )
        ),
        this.key("cryptData").octstr()
    );
});

var pbes2_parse = function (data) {
    var asn1, kdf, enc, params, iv, sbox, salt, iter;

    asn1 = PBES2.decode(data, 'der');
    if (asn1.head.id !== 'PBES2') {
        throw new Error(asn1.head.id);
    }
    kdf = asn1.head.pbes2.keyDerivationFunc;
    if (kdf.id !== 'PBKDF2') {
        throw new Error(asn1.head.p.key.id);
    }
    if (kdf.params.hash.algorithm !== 'Gost34311-hmac') {
        throw new Error("Unknown cipher " + kdf.params.algorithm);
    }
    enc = asn1.head.pbes2.encryptionScheme;
    if (enc.algorithm !== 'Gost28147-cfb') {
        throw new Error(asn1.head.p.cipher.id);
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
        "body": asn1.cryptData,
    };
};

var pbes2_parse_wrapped = function (data) {
    return pbes2_parse(data.slice(82));
}

var pbes2_serialize = function(store) {
    return PBES2.encode({
      head: {
        id: 'PBES2',
        pbes2: {
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
        },
      },
      cryptData: store.body,
    }, 'der');
}

module.exports = PBES2;
module.exports.enc_parse = pbes2_parse;
module.exports.enc_parse2 = pbes2_parse_wrapped;
module.exports.enc_serialize = pbes2_serialize;
