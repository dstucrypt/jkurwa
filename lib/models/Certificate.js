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

var OID_LINK = {
    '1 3 6 1 5 5 7 48 1': 'ocsp',
    '1 3 6 1 5 5 7 48 2': 'issuers',
    '1 3 6 1 5 5 7 48 3': 'tsp',
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

var Link = asn1.define('Link', function () {
    this.seq().obj(
        this.key('id').objid(OID_LINK),
        this.key('link').implicit(6).ia5str()
    );
});

var AIA = asn1.define('AIA', function () {
    this.seqof(Link);
});

var str = function (buf) {
    var off = 2;
    if (buf[1] & 0x80) {
        off += buf[1] ^ 0x80;
    }
    if (buf[0] == 0xC) {
        return buf.slice(off).toString('utf8');
    }
    return buf.slice(off).toString('binary');
};


var formatRDN = function (serial, rdnlist) {
    var ret = serial.toString(16);

    var part = [];
    rdnlist.map(function (elements) {
        elements.map(function (el) {
            part.push(el.type + '=' + str(el.value));
        });
    });

    return ret + '@' + part.join('/');
};


var Certificate = function (cert, lazy) {
    this.setup(cert, lazy);
    this._raw = cert._raw;
    delete cert._raw;
};

Certificate.prototype.setup = function (cert, lazy) {
    var tbs = cert.tbsCertificate,
        pk = tbs.subjectPublicKeyInfo,
        pk_data = pk.subjectPublicKey.data.slice(2);


    this.format = "x509";
    this.curve = (pk.algorithm.algorithm === 'Dstu4145le')
        ? jk.Curve.resolve(pk.algorithm.parameters.curve, 'cert')
        : null;
    this.curve_id = (pk.algorithm.algorithm === 'ECDSA')
        ? pk.algorithm.parameters.value
        : null;
    this.pk_data = util.BIG_LE(pk_data);
    this.valid = {
            from: tbs.validity.notBefore.value,
            to: tbs.validity.notAfter.value
        };
    this.serial = cert.tbsCertificate.serialNumber;
    this.signatureAlgorithm = cert.signatureAlgorithm.algorithm;
    this.pubkeyAlgorithm = cert.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm;
    this.extension = this.parse_ext(cert.tbsCertificate.extensions);
    this.issuer = this.parse_dn(cert.tbsCertificate.issuer.value);
    this.subject = this.parse_dn(cert.tbsCertificate.subject.value);
    this.ob = cert;
    if (!lazy && this.curve) {
        this.pubkey_unpack();
    }
};

Certificate.prototype.pubkey_unpack = function pubkey_unpack () {
    if (!this.pubkey) this.pubkey = this.curve.pubkey(this.pk_data);
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
    if (ret.authorityInfoAccess !== undefined) {
        this.parse_aia(ret.authorityInfoAccess, ret);
    }
    if (ret.subjectInfoAccess !== undefined) {
        this.parse_aia(ret.subjectInfoAccess, ret);
    }
    return ret;
};

Certificate.prototype.parse_aia = function (data, upd) {
    var asn_aia = AIA.decode(data, 'der');
    return asn_aia.reduce(function (acc, item) {
        acc[item.id] = item.link;
        return acc;
    }, upd || {});
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


Certificate.prototype.rdnSerial = function () {
    return formatRDN(this.ob.tbsCertificate.serialNumber, this.ob.tbsCertificate.issuer.value);

};


Certificate.from_asn1 = function (data) {
    var cert = rfc3280.Certificate.decode(data, 'der');
    cert._raw = data;
    return new Certificate(cert);

};

Certificate.from_pem = function (data) {
    return Certificate.from_asn1(pem.maybe_pem(data));
};

Certificate.prototype.name_asn1 = function () {
    return rfc3280.Name.encode(this.ob.tbsCertificate.issuer, 'der');
};


module.exports = Certificate;
module.exports.formatRDN = formatRDN;
