/*jslint plusplus: true */
'use strict';

var Big = require('../../3rtparty/jsbn.packed.js'),
    asn1 = require('asn1.js'),
    util = require('../util.js');

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
    var ob, meth;

    meth = {
        setup: function (cert) {
            var tbs = cert.tbsCertificate,
                pub = tbs.subjectPublicKeyInfo.subjectPublicKey.data.slice(2);
            return {
                format: "x509",
                pubkey: new Big(util.add_zero(pub, true)),
                valid: {
                    from: tbs.validity.notBefore.value,
                    to: tbs.validity.notAfter.value
                },
                extension: meth.parse_ext(cert.tbsCertificate.extensions.e),
                issuer: meth.parse_dn(cert.tbsCertificate.issuer.value),
                subject: meth.parse_dn(cert.tbsCertificate.subject.value)
            };
        },
        parse_ipn: function (data) {
            var i, part,
                ret = {},
                asn_ib = IPN.decode(data, 'der');

            for (i = 0; i < asn_ib.length; i++) {
                part = asn_ib[i];
                ret[part.id] = String.fromCharCode.apply(null, part.val[0]);
            }
            return ret;
        },
        parse_ext: function (asn_ob) {
            var ret, i, part;
            ret = {};
            for (i = 0; i < asn_ob.length; i++) {
                part = asn_ob[i];
                ret[part.extnID] = part.extnValue;
            }
            if(ret.subjectDirectoryAttributes !== undefined) {
                ret.ipn = meth.parse_ipn(ret.subjectDirectoryAttributes);
            }
            return ret;
        },
        parse_dn: function (asn_ob) {
            var ret, i, j, part;
            ret = {};
            for (i = 0; i < asn_ob.length; i++) {
                for (j = 0; j < asn_ob[i].length; j++) {
                    part = asn_ob[i][j];
                    if ((part.value[0] === 0xC) && part.value[1] === part.value.length - 2) {
                        ret[part.type] = meth.strFromUtf8Ab(part.value.slice(2));
                    } else {
                        ret[part.type] = part.value;
                    }
                }
            }
            return ret;
        },
        strFromUtf8Ab: function (ab) {
            return decodeURIComponent(escape(String.fromCharCode.apply(null, ab)));
        }
    };

    ob = meth.setup(cert);

    return ob;
};

module.exports = Certificate;
