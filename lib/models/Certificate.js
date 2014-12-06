/*jslint plusplus: true */
'use strict';

var jk = require('../curve.js'),
    rfc3280 = require('../spec/rfc3280.js'),
    asn1 = require('asn1.js'),
    util = require('../util.js'),
    pem = require('../util/pem'),
    b64_encode = require('../util/base64.js').b64_encode;

var OID = {
    '1 2 804 2 1 1 1 11 1 4 1 1': 'DRFO',
    '1 2 804 2 1 1 1 11 1 4 2 1': 'EDRPOU',
};

var IPN_VAL = asn1.define('IPN_VAL', function () {
    this.implicit(0x13).octstr();
});

var IPN_ID = asn1.define('IPN_ID', function () {
    this.seq().obj(
        this.key('id').objid(OID),
        this.key("val").setof(IPN_VAL)
    );
});

var IPN = asn1.define('IPN', function () {
    this.seqof(IPN_ID);
});

var Certificate = function (cert) {
    this.setup(cert);
    this._raw = cert._raw;
    delete cert._raw;
};

Certificate.prototype.setup = function (cert) {
    var tbs = cert.tbsCertificate,
        pk = tbs.subjectPublicKeyInfo,
        pk_data = pk.subjectPublicKey.data.slice(2);

    var curve = jk.Curve.from_asn1(pk.algorithm.parameters.curve, 'cert');
    var pub = curve.pubkey(util.BIG_LE(pk_data), 'raw');

    this.format = "x509";
    this.pubkey = pub;
    this.valid = {
            from: tbs.validity.notBefore.value,
            to: tbs.validity.notAfter.value
        };
    this.extension = this.parse_ext(cert.tbsCertificate.extensions);
    this.issuer = this.parse_dn(cert.tbsCertificate.issuer.value);
    this.subject = this.parse_dn(cert.tbsCertificate.subject.value);
    this.ob = cert;
};

Certificate.prototype.parse_ipn = function (data) {
    var i, part,
        ret = {},
        asn_ib = IPN.decode(data, 'der');

    for (i = 0; i < asn_ib.length; i++) {
        part = asn_ib[i];
        ret[part.id] = String.fromCharCode.apply(null, part.val[0]);
    }
    return ret;
};

Certificate.prototype.parse_ext = function (asn_ob) {
    var ret, i, part;
    ret = {};
    for (i = 0; i < asn_ob.length; i++) {
        part = asn_ob[i];
        ret[part.extnID] = part.extnValue;
    }
    if(ret.subjectDirectoryAttributes !== undefined) {
        ret.ipn = this.parse_ipn(ret.subjectDirectoryAttributes);
    }
    return ret;
};

Certificate.prototype.parse_dn = function (asn_ob) {
    var ret, i, j, part;
    ret = {};
    for (i = 0; i < asn_ob.length; i++) {
        for (j = 0; j < asn_ob[i].length; j++) {
            part = asn_ob[i][j];
            if ((part.value[0] === 0xC) && part.value[1] === part.value.length - 2) {
                ret[part.type] = util.strFromUtf8(part.value.slice(2));
                continue;
            }
            if ((part.value[0] === 0x13 && part.value[1] === part.value.length - 2)) {
                ret[part.type] = part.value.slice(2).toString();
                continue;
            }
            else {
                ret[part.type] = part.value;
            }
        }
    }
    return ret;
};

Certificate.prototype.as_asn1 = function() {
    if(this._raw !== undefined) {
        return this._raw;
    }

    return rfc3280.Certificate.encode(this.ob, 'der');
};
Certificate.prototype.to_asn1 = Certificate.prototype.as_asn1;

Certificate.prototype.as_pem = function () {
    return (
        '-----BEGIN CERTIFICATE-----\n' +
        b64_encode(this.to_asn1(), {line: 16, pad: true}) +
        '\n-----END CERTIFICATE-----'
    );
};
Certificate.prototype.to_pem = Certificate.prototype.as_pem;

Certificate.prototype.as_dict = function () {
    var x = this;
    return {
        subject: x.subject,
        issuer: x.issuer,
        extension: x.extension,
        valid: x.valid,
    };
};

Certificate.prototype.nameSerial = function() {
    return {
        issuer: this.ob.tbsCertificate.issuer,
        serialNumber: this.ob.tbsCertificate.serialNumber,
    };
};

Certificate.from_asn1 = function (data) {
    var cert = rfc3280.Certificate.decode(data, 'der');
    cert._raw = data;
    return new Certificate(cert);

};

Certificate.from_pem = function (data) {
    return Certificate.from_asn1(pem.maybe_pem(data));
};

module.exports = Certificate;
