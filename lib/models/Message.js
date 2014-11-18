/*jslint plusplus: true, bitwise: true */
'use strict';

var dstszi2010 = require('../spec/dstszi2010.js'),
    rfc3280 = require('../spec/rfc3280'),
    certid = require('../spec/rfc5035-certid.js'),
    ContentInfo = dstszi2010.ContentInfo,
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
    var ob, parse, unpack, signer, as_asn1, construct, certv2,
        contentType, digestAttr, tspAttr, timeAttr;

    construct = function(ob) {
        var signB = ob.signB; // TODO: calc here
        var digestB = ob.digestB; // TODO: calc here
        var tspB = ob.tspB; // TODO: get from network

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
                    issuerAndSerialNumber: ob.cert.nameSerial(),
                    digestAlgorithm: { algorithm: 'Gost34311' },
                    digestEncryptionAlgorithm: { algorithm: 'Dstu4145le' },
                    encryptedDigest: signB,
                    authenticatedAttributes: [
                        this.certv2(ob.cert, ob.certhash),
                        this.contentType('data'),
                        this.digestAttr(digestB),
                        this.tspAttr(tspB),
                        this.timeAttr(ob.signTime)
                    ]
                }]
            },
        };
        this.wrap = wrap;
        this.info = wrap.content;
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

    ob = {
        parse: parse,
        construct: construct,
        certv2: certv2,
        contentType: contentType,
        digestAttr: digestAttr,
        tspAttr: tspAttr,
        timeAttr: timeAttr,
        type: null,
        info: null,
        unpack: unpack,
        signer: signer,
        as_asn1: as_asn1
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
