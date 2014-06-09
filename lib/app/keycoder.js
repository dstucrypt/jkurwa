/*jslint plusplus: true, bitwise: true */
'use strict';

var asn1 = require('asn1.js'),
    Buffer = require('buffer').Buffer,
    Big = require('../../3rtparty/jsbn.packed.js'),
    rfc3280 = require('../spec/rfc3280.js'),
    PBES2 = require('../spec/pbes.js'),
    DstuPrivkey = require('../spec/keystore.js'),
    b64_decode = require('../util/base64.js').b64_decode,
    models = require('../models/index.js'),
    util = require('../util.js');


var Keycoder = function () {

    var ob, OID;

    OID = {
        "1 3 6 1 4 1 19398 1 1 1 2": "IIT Store",
        '1 2 840 113549 1 5 13': "PBES2",
        "1 2 840 113549 1 5 12": "PBKDF2",
        '1 2 804 2 1 1 1 1 1 2': "GOST_34311_HMAC",
        '1 2 804 2 1 1 1 1 1 1 3': "GOST_28147_CFB",
        '1 2 804 2 1 1 1 1 3 1 1': "DSTU_4145_LE",
    };

    ob = {
        StoreIIT: asn1.define('StoreIIT', function () {
            this.seq().obj(
                this.key('cryptParam').seq().obj(
                    this.key('cryptType').objid(OID),
                    this.key('cryptParam').seq().obj(
                        this.key('mac').octstr(),
                        this.key('pad').octstr()
                    )
                ),
                this.key('cryptData').octstr()
            );
        }),
        to_pem: function (b64, desc) {
            var begin, end;
            if (desc === undefined) {
                desc = 'PRIVATE KEY';
            }
            begin = '-----BEGIN ' + desc + '-----';
            end = '-----END ' + desc + '-----';

            return [begin, b64, end].join('\n');
        },
        is_valid : function (indata) {
            return (indata[0] === 0x30) && ((indata[1] & 0x80) === 0x80);
        },
        iit_parse: function (data) {

            var asn1 = ob.StoreIIT.decode(data, 'der'), mac, pad;
            mac = asn1.cryptParam.cryptParam.mac;
            pad = asn1.cryptParam.cryptParam.pad;

            if (mac.length !== 4) {
                throw new Error("Invalid mac len " + mac.length);
            }
            if (pad.length >= 8) {
                throw new Error("Invalid pad len " + pad.length);
            }
            if (asn1.cryptParam.cryptType !== 'IIT Store') {
                throw new Error("Invalid storage type");
            }

            return {
                "format": "IIT",
                "mac": mac,
                "pad": pad,
                "body": asn1.cryptData,
            };
        },
        pbes2_parse: function (data) {
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
                "iters": iter,
                "body": asn1.cryptData,
            };
        },
        parse_ks: function (ks) {
            if (ks.type === 'trinominal') {
                return [ks.value];
            }
            return [ks.value.k1, ks.value.k2, ks.value.k3];
        },
        privkey_attr_parse: function (attr) {
            var ahash = {}, i, aob, priv1_d, dstu;
            for (i = 0; i < attr.length; i++) {
                aob = attr[i];
                if (aob.id !== undefined) {
                    ahash[aob.id] = aob.value[0].value;
                }
            }
            if (!ahash.DSTU_4145_KEY_BITS) {
                return undefined;
            }

            if (ahash.DSTU_4145_CURVE === undefined) {
                return undefined;
            }

            priv1_d = ahash.DSTU_4145_KEY_BITS.data;
            dstu = ahash.DSTU_4145_CURVE;

            return {
                param_d: new Big(util.add_zero(util.invert(priv1_d))),
                curve : {
                    m: dstu.curve.p.param_m,
                    ks: ob.parse_ks(dstu.curve.p.ks),
                    k1: dstu.curve.p.ks.value.k1,
                    a: new Big([dstu.curve.param_a]),
                    b: new Big(util.add_zero(dstu.curve.param_b)),
                    order: new Big(util.add_zero(dstu.curve.order)),
                    base: new Big(util.add_zero(dstu.curve.bp)),
                },
                format: "privkey",
            };
        },
        privkey_parse: function (data) {
            var key0, key1, priv;

            priv = DstuPrivkey.decode(data, 'der');
            key1 = ob.privkey_attr_parse(priv.attr);

            key0 = {
                param_d: new Big(util.add_zero(priv.param_d, true)),
                curve: {
                    m: priv.priv0.p.p.p.param_m,
                    k1: ob.parse_ks(priv.priv0.p.p.p.ks)[0],
                    ks: ob.parse_ks(priv.priv0.p.p.p.ks),
                    a: new Big([priv.priv0.p.p.param_a]),
                    b: new Big(util.add_zero(priv.priv0.p.p.param_b, true)),
                    order: new Big(util.add_zero(priv.priv0.p.p.order)),
                    base: new Big(util.add_zero(priv.priv0.p.p.bp, true)),
                },
                sbox: priv.priv0.p.sbox,
                format: "privkey",
            };

            return {
                keys: key1 ? [key0, key1] : [key0],
                format: "privkeys",
            };
        },
        cert_parse: function (data) {
            var cert = rfc3280.Certificate.decode(data, 'der');
            return new models.Certificate(cert);
        },
        is_pem: function (indata) {
            if (indata.constructor === Uint8Array) {
                if ((indata[0] === 0x2D) &&
                        (indata[1] === 0x2D) &&
                        (indata[2] === 0x2D) &&
                        (indata[3] === 0x2D) &&
                        (indata[4] === 0x2D)) {
                    return true;
                }
            }
            if ((typeof indata) === 'string') {
                return indata.indexOf('-----') === 0;
            }
        },
        maybe_pem: function (indata) {
            var start, end, ln;

            if (ob.is_pem(indata) !== true) {
                return indata;
            }
            if ((typeof indata) !== 'string') {
                indata = String.fromCharCode.apply(null, indata);
            }
            indata = indata.split('\n');
            for (start = 0; start < indata.length; start++) {
                ln = indata[start];
                if (ln.indexOf('-----') === 0) {
                    start++;
                    break;
                }
            }

            for (end = 1; end <= indata.length; end++) {
                ln = indata[indata.length - end];
                if (ln.indexOf('-----') === 0) {
                    break;
                }
            }

            indata = indata.slice(start, -end).join('');
            return b64_decode(indata);
        },
        guess_parse: function (indata) {
            var data, tr, i;
            data = new Buffer(indata, 'raw');

            tr = [
                'iit_parse',
                'pbes2_parse',
                'privkey_parse',
                'cert_parse',
            ];

            for (i = 0; i < tr.length; i++) {
                try {
                    return ob[tr[i]](data);
                } catch (ignore) {}
            }

            throw new Error("Unknown format");
        },
    };
    return {
        "parse": ob.guess_parse,
        "to_pem": ob.to_pem,
        "is_valid": ob.is_valid,
        "maybe_pem": ob.maybe_pem,
    };
};

module.exports = Keycoder;
