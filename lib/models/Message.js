/*jslint plusplus: true, bitwise: true */
'use strict';

var dstszi2010 = require('../spec/dstszi2010.js'),
    rfc3280 = require('../spec/rfc3280'),
    certid = require('../spec/rfc5035-certid.js'),
    ContentInfo = dstszi2010.ContentInfo,
    transport = require('../util/transport'),
    util = require('../util.js'),
    Certificate = require('./Certificate.js');

/*
    Need spec for this. This is something like key=value document
    with magic header, key-value pairs and body
*/
var prefixed_with = function (buffer, prefix, idx) {
    idx = idx || 0;
    var sliced = buffer.slice(idx, idx + prefix.length);

    return sliced.toString() === prefix;
};

var decode_transport = function (buffer, wait_label) {
    var i = 0, skip = 2;
    if (wait_label) {
        for (i = 0; i < buffer.length; i++) {
            if (prefixed_with(buffer, wait_label, i)) {
                break;
            }
        }
    }
    for (i; i < buffer.length; i++) {
        if (skip) {
            if (buffer[i] === 0) {
                skip -= 1;
            }
        } else {
            if (buffer[i] !== 0) {
                break;
            }
        }
    }
    return {
        type: "taxTransport",
        contents: buffer.slice(i),
    };
};

var Message = function (asn1_ob) {
    var ob, parse, unpack, verify, decrypt, signer, as_asn1, as_transport, mhash,
        construct, constructSigned, constructEnveloped,
        certv2, contentType, digestAttr, tspAttr, timeAttr;

    construct = function(ob) {
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

    constructEnveloped = function(ob) {
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

    constructSigned = function(ob) {
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
            var digestS = this.mhash(ob.hash, ob.data, authenticatedAttributes);
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

    digestAttr = function(digestB) {
        digestB =  dstszi2010.Data.encode(digestB, 'der');

        return {
            type: 'messageDigest',
            values: [digestB]
        };
    };

    tspAttr = function(tspB) {
        return {
            type: 'contentTimeStamp',
            values: [tspB]
        };
    };

    timeAttr = function(time) {
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

    contentType = function (ct) {
        var obid = dstszi2010.ContentType.encode(ct, 'der');
        return { type: 'contentType', values: [obid] };
    };

    certv2 = function(cert, chash) {
        return {
            type: 'signingCertificateV2',
            values: [certid.SigningCertificateV2.wrap(cert.ob, chash)]
        };
    };

    parse = function (data) {
        var s_content_info;

        if (prefixed_with(data, 'TRANSPORTABLE\x00')) {
            data = decode_transport(data, 'UA1_SIGN\x00').contents;
        }
        if (prefixed_with(data, 'UA1_CRYPT\x00')) {
            data = data.slice(14);
        }

        s_content_info = ContentInfo.decode(data, 'der');

        ob.wrap = s_content_info;
        ob.type = s_content_info.contentType;
        ob.info = s_content_info.content;

        if (ob.type === 'envelopedData') {
            // extract encryption params from asn1
            ob.enc_info = ob.info.encryptedContentInfo;
            ob.enc_params = ob.enc_info.contentEncryptionAlgorithm.parameters.value;
            if (ob.info.recipientInfos.length === 1) {
                ob.rki = ob.info.recipientInfos[0].value;
            }
            ob.enc_contents = ob.info.encryptedContentInfo.encryptedContent;
        }
        if (ob.type === 'signedData') {
            ob.attrs = ob.info.signerInfos[0].authenticatedAttributes;
        }
    };

    mhash = function (hash_f, data, attrs) {
        var dataToSign;
        if (attrs || this.attrs) {
            dataToSign = dstszi2010.Attributes.encode(attrs || this.attrs, 'der');
        } else {
            dataToSign = data || this.info.contentInfo.content;

        }
        return hash_f(dataToSign);
    };

    verify = function (hash_f) {
        var hash = this.mhash(hash_f),
            cert = this.signer();
        return cert.pubkey.verify(hash, this.info.signerInfos[0].encryptedDigest, 'le');
    };

    decrypt = function(crypter, algo) {
        var pubkey;
        if(this.cert) {
            pubkey = this.cert.pubkey;
        } else {
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

    unpack = function () {
        if (ob.type === 'signedData') {
            var buffer = ob.info.contentInfo.content.value,
                data;

            if (prefixed_with(buffer, 'UA1_CRYPT\x00')) {
                data = decode_transport(buffer);
                if ((data.contents[0] === 0x30) && (data.contents[1] & 0x80)) {
                    try {
                        return new Message(data.contents);
                    } catch (ignore) { }
                }
                return data;
            }
            return buffer;
        }
        if (ob.type === 'envelopedData') {
            return ob.enc_contents;
        }
    };

    signer = function () {
        return new Certificate(ob.info.certificate);
    };

    as_asn1 = function() {
        var buf = ContentInfo.encode(ob.wrap, 'der');
        return buf;
    };

    as_transport = function(opts) {
        var docs = [],
            add_cert = false,
            magic;
        if (typeof opts === 'object') {
            add_cert = opts.add_cert === true;
            if (opts.add_cert !== undefined) {
                delete opts.add_cert;
            }
        }
        if (opts === true || opts === false) {
            add_cert = opts;
            opts = undefined;
        }

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

    ob = {
        parse: parse,
        construct: construct,
        constructSigned: constructSigned,
        constructEnveloped: constructEnveloped,
        certv2: certv2,
        contentType: contentType,
        digestAttr: digestAttr,
        tspAttr: tspAttr,
        timeAttr: timeAttr,
        type: null,
        info: null,
        unpack: unpack,
        decrypt: decrypt,
        verify: verify,
        signer: signer,
        as_asn1: as_asn1,
        as_transport: as_transport,
        mhash: mhash,
    };

    if (Buffer.isBuffer(asn1_ob)) {
        ob.parse(asn1_ob);
    } else {
        if (typeof asn1_ob  === 'object') {
            ob.construct.bind(ob)(asn1_ob);
        }
    }

    return ob;
};

module.exports =  Message;
