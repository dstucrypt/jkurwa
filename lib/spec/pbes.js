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
                        this.key("hash").use(CipherParams)
                    )
                ),
                this.key("encryptionScheme").use(CipherParams)
            )
        ),
        this.key("cryptData").octstr()
    );
});

module.exports = PBES2;
