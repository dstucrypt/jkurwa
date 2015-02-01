/*jslint plusplus: true, bitwise: true */
'use strict';

var dstszi2010 = require('../spec/dstszi2010.js'),
    rfc3280 = require('../spec/rfc3280'),
    certid = require('../spec/rfc5035-certid.js'),
    ContentInfo = dstszi2010.ContentInfo,
    transport = require('../util/transport'),
    util = require('../util.js'),
    Certificate = require('./Certificate.js');


var flatAttr = function (attrs) {
    var ret = {};
    attrs.map(function(el) {
        ret[el.type] = el.values[0];
    });
    return ret;
};

var Message = function (asn1_ob) {

    this.type = null;
    this.info = null;
    if (Buffer.isBuffer(asn1_ob)) {
        this.parse(asn1_ob);
    } else {
        if (typeof asn1_ob  === 'object') {
           this.construct(asn1_ob);
        }
    }

};

Message.prototype.construct = function(ob) {
    if(ob.type === 'signedData') {
        this.constructSigned(ob);
    }
    if(ob.type === 'envelopedData') {
        this.constructEnveloped(ob);
    }
    this.info = this.wrap.content;
    this.type = this.wrap.contentType;
    this.cert = ob.cert;
};

Message.prototype.constructEnveloped = function(ob) {
    var cert = ob.cert,
        algo = cert.ob.tbsCertificate.subjectPublicKeyInfo.algorithm,
        dke = algo.parameters.dke;

    var enc = ob.crypter.encrypt(ob.data, ob.toCert, ob.algo);
    var kari = {
        version: 3,
        originator: {
            type: 'issuerAndSerialNumber',
            value: cert.nameSerial()
        },
        ukm: enc.ukm,
        keyEncryptionAlgorithm: {
            algorithm: 'dhSinglePass-cofactorDH-gost34311kdf',
            parameters: {
                algorithm: 'Gost28147-cfb-wrap',
                parameters: null
            }
        },
        recipientEncryptedKeys: [{
            rid: {
                type: 'issuerAndSerialNumber',
                value: ob.toCert.nameSerial(),
            },
            encryptedKey: enc.wcek,
        }]
    };

    var wrap = {
        contentType: ob.type,
        content: {
            version: 2,
            recipientInfos: [{
                type: 'kari',
                value: kari,
            }],
            encryptedContentInfo: {
                contentType: 'data',
                encryptedContent: enc.data,
                contentEncryptionAlgorithm: {
                    algorithm: 'Gost28147-cfb',
                    parameters: {
                        type: 'params',
                        value: {
                            iv: enc.iv,
                            dke: dke,
                        }
                    },
                },
            }
        }
    };
    this.wrap = wrap;
    this.info = wrap.content;
};

Message.prototype.constructSigned = function(ob) {
    var signB = ob.signB;
    var digestB = ob.hash(ob.data);
    var tspB = ob.tspB; // TODO: get from network

    var authenticatedAttributes = [
        this.certv2(ob.cert, ob.hash(ob.cert.as_asn1())),
        this.contentType('data'),
        this.digestAttr(digestB),
        //this.tspAttr(tspB, digestB),
        this.timeAttr(ob.signTime)
    ];
    if (signB === undefined) {
        this.attrs = authenticatedAttributes;
        this.info = {
            contentInfo: {content: ob.data}
        };
        var digestS = this.mhash(ob.hash);
        signB = ob.signer.sign(digestS, 'le');
    }

    var wrap = {
        contentType: ob.type,
        content: {
            version: 1,
            digestAlgorithms : [{ algorithm: 'Gost34311' }],
            contentInfo: {
                contentType: 'data',
                content: ob.data,
            },
            certificate: ob.cert.ob,
            signerInfos: [{
                version: 1,
                sid: {
                    type: 'issuerAndSerialNumber',
                    value: ob.cert.nameSerial(),
                },
                digestAlgorithm: { algorithm: 'Gost34311' },
                digestEncryptionAlgorithm: { algorithm: 'Dstu4145le' },
                encryptedDigest: signB,
                authenticatedAttributes: authenticatedAttributes,
            }]
        },
    };
    this.wrap = wrap;
    this.info = wrap.content;
    this.attrs = authenticatedAttributes;
};


Message.prototype.digestAttr = function(digestB) {
    digestB =  dstszi2010.Data.encode(digestB, 'der');

    return {
        type: 'messageDigest',
        values: [digestB]
    };
};

Message.prototype.tspAttr = function(tspB) {
    return {
        type: 'contentTimeStamp',
        values: [tspB]
    };
};

Message.prototype.timeAttr = function(time) {
    if(time !== undefined) {
        time = new Date(1000 * time);
    } else {
        time = new Date();
    }

    var timeB = rfc3280.Time.encode({'type': 'utcTime', value: time}, 'der');
    return {
        type: 'signingTime',
        values: [timeB],
    };
};

Message.prototype.contentType = function (ct) {
    var obid = dstszi2010.ContentType.encode(ct, 'der');
    return { type: 'contentType', values: [obid] };
};

Message.prototype.certv2 = function(cert, chash) {
    return {
        type: 'signingCertificateV2',
        values: [certid.SigningCertificateV2.wrap(cert.ob, chash)]
    };
};

Message.prototype.parse = function (data) {
    var s_content_info;

    s_content_info = ContentInfo.decode(data, 'der');

    this.wrap = s_content_info;
    this.type = s_content_info.contentType;
    this.info = s_content_info.content;

    if (this.type === 'envelopedData') {
        // extract encryption params from asn1
        this.enc_info = this.info.encryptedContentInfo;
        this.enc_params = this.enc_info.contentEncryptionAlgorithm.parameters.value;
        if (this.info.recipientInfos.length === 1) {
            this.rki = this.info.recipientInfos[0].value;
        }
        this.enc_contents = this.info.encryptedContentInfo.encryptedContent;
    }
    if (this.type === 'signedData') {
        this.attrs = this.info.signerInfos[0].authenticatedAttributes;
    }
    this.parseAttrs();
};

Message.prototype.mhash = function (hash_f) {
    var dataToSign;
    if (this.attrs) {
        dataToSign = dstszi2010.Attributes.encode(this.attrs, 'der');
    } else {
        dataToSign = this.info.contentInfo.content;
    }
    return hash_f(dataToSign);
};

Message.prototype.parseAttrs = function () {
    if (!this.attrs) {
        return;
    }

    var pattrs = {};
    this.attrs.map((function (el) {
        var meth = el.type.substr(0, 1).toUpperCase();
        meth = 'parse' + meth + el.type.substr(1);
        if (this[meth]) {
            pattrs[el.type] = this[meth](el.values[0]);
        }
    }).bind(this));

    this.pattrs = pattrs;
};

Message.prototype.parseMessageDigest = function (messageDigest) {
    if (messageDigest[0] !== 0x04 || messageDigest[1] !== messageDigest.length - 2) {
        return undefined;
    }

    return messageDigest.slice(2);
};

Message.prototype.parseSigningTime = function (stime) {
    return rfc3280.Time.decode(stime, 'der').value;
};

Message.prototype.verifyAttrs = function (hash_f) {
    if (!this.attrs) {
        return true;
    }

    var ok;
    ok = this.verifyAttrDigest(this.pattrs.messageDigest, hash_f);
    ok = ok && this.verifySigningTime(this.pattrs.signingTime);

    return ok;
};

Message.prototype.verifyAttrDigest = function (dgst, hash_f) {
    if (!dgst) {
        return false;
    }
    var dataToSign = this.info.contentInfo.content;
    var hashbuf = hash_f(dataToSign);
    var xor = 0, idx = 0;
    for (idx = 0; idx < dgst.length; idx++) {
        xor = dgst[idx] ^ hashbuf[idx];
    }
    return xor === 0;
};

Message.prototype.verifySigningTime = function (time) {
    if (!time) {
        return true;
    }
    var x509 = this.signer();
    return time >= x509.valid.from && time <= x509.valid.to;
};

Message.prototype.verify = function (hash_f) {
    var hash = this.mhash(hash_f),
        cert = this.signer();

    if (!this.verifyAttrs(hash_f)) {
        return false;
    }
    return cert.pubkey.verify(hash, this.info.signerInfos[0].encryptedDigest, 'le');
};

Message.prototype.decrypt = function(crypter, algo, lookupCert) {
    var pubkey;
    var ri = this.info.recipientInfos[0];
    if (ri.value.originator.type === 'issuerAndSerialNumber') {
        pubkey = lookupCert(ri.value.originator.value);
        if (!pubkey) {
            throw new ENOCERT();
        }
        pubkey = pubkey.pubkey;
    }
    if (ri.value.originator.type === 'originatorKey') {
        var originator = this.info.recipientInfos[0].value.originator;
        pubkey = originator.value.publicKey.data.slice(2);
        pubkey = crypter.curve.pubkey(util.add_zero(pubkey, true), 'buf8');
    }
    var enc = this.info.encryptedContentInfo,
        enc_param = enc.contentEncryptionAlgorithm.parameters.value;

    var rp = this.info.recipientInfos[0].value.recipientEncryptedKeys[0];
    var p = {
        ukm: this.info.recipientInfos[0].value.ukm,
        iv: enc_param.iv,
        wcek: rp.encryptedKey,
    };
    return crypter.decrypt(enc.encryptedContent, pubkey, p, algo);
};

Message.prototype.signer = function () {
    return new Certificate(this.info.certificate);
};


Message.prototype.as_asn1 = function() {
    var buf = ContentInfo.encode(this.wrap, 'der');
    return buf;
};

Message.prototype.as_transport = function(opts, add_cert) {
    var docs = [],
        magic;

    if (this.type === 'signedData') {
        magic = 'UA1_SIGN';
    }
    if (this.type === 'envelopedData') {
        magic = 'UA1_CRYPT';
    }
    if (add_cert) {
        docs.push({type: 'CERTCRYPT', contents: this.cert.as_asn1()});
    }
    docs.push({type: magic, contents: this.as_asn1()});
    return transport.encode(docs, opts);
};

var ENOCERT = function () {
};
ENOCERT.prototype = new Error;

module.exports =  Message;
module.exports.ENOCERT = ENOCERT;
