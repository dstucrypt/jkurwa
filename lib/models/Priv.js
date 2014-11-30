/*jslint plusplus: true */
'use strict';

var jk = require('../curve.js'),
    bn = require('bn.js'),
    util = require('../util.js'),
    pem = require('../util/pem'),
    b64_encode = require('../util/base64.js').b64_encode,
    dstszi2010 = require('../spec/dstszi2010.js'),
    ks = require('../spec/keystore.js'),
    DstuPrivkey = ks.DstuPrivkey,
    Pub = require('./Pub.js'),
    Field = jk.Field;


var gost_salt = function (ukm) {
    return dstszi2010.SharedInfo.encode({
        "keyInfo": {
            "algorithm": "Gost28147-cfb-wrap",
            "parameters": null,
        },
        "entityInfo": ukm || undefined,
        "suppPubInfo": new Buffer("\x00\x00\x01\x00"),
    }, 'der');

};


var detect_format = function (inp) {
    if (util.is_hex(inp) === true) {
        return 'hex';
    }
    throw new Error("Unknown privkey format");
};

var attr_parse = function (attr) {
    var ahash = {}, i, aob, priv1_d, dstu, curve;
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
    if(priv1_d === undefined || priv1_d.length === 0) {
        return undefined;
    }

    curve = new jk.Curve.from_asn1(dstu.curve);

    return curve.pkey(util.BIG_INVERT(priv1_d), 'buf8');
};

var from_asn1 = function (data, return_store) {
    var key0, key1, priv, curve;

    priv = DstuPrivkey.decode(data, 'der');
    curve = new jk.Curve({
        m: priv.priv0.p.p.p.param_m,
        ks: jk.Curve.ks_parse(priv.priv0.p.p.p.ks),
        a: [priv.priv0.p.p.param_a],
        b: util.BIG_LE(priv.priv0.p.p.param_b),
        order: util.BIG_BE(priv.priv0.p.p.order.toArray()),
        kofactor: [4],
        base: util.BIG_LE(priv.priv0.p.p.bp),
    });
    key0 = curve.pkey(util.BIG_LE(priv.param_d), 'buf32');
    if (return_store !== true) {
        return key0;
    }

    key1 = attr_parse(priv.attr);
    return {
        keys: key1 ? [key0, key1] : [key0],
        format: "privkeys",
    };
};

var short_sign = function (sign, raw) {
    var tmp_s, tmp_r, mlen, sbuf, idx, tmp;
    tmp_s = sign.s.truncate_buf8();
    tmp_r = sign.r.truncate_buf8();
    mlen = Math.max(tmp_s.length, tmp_r.length);
    sbuf = new Buffer(2 + (mlen * 2));
    sbuf.writeUInt8(4, 0);
    sbuf.writeUInt8(mlen * 2, 1);

    for (idx = 0; idx < mlen; idx++) {
        tmp = tmp_r[mlen - idx - 1];
        sbuf.writeUInt8(tmp < 0 ? 256 + tmp : tmp, idx + 2);
    }

    for (idx = 0; idx < mlen; idx++) {
        tmp = tmp_s[mlen - idx - 1];
        sbuf.writeUInt8(tmp < 0 ? 256 + tmp : tmp, idx + 2 + mlen);
    }
    if(raw) {
        return sbuf.slice(2);
    }

    return sbuf;
};

var sign_serialise = function (data, fmt) {
    if(fmt === 'short' || fmt === 'le') {
        return short_sign(data, fmt === 'le');
    }

    throw new Error("Unkown signature format " + fmt);
};

var Priv = function (p_curve, param_d) {
    var ob,
        help_sign = function (hash_v, rand_e) {
            var eG, r, s, big_d, big_rand_e, big_order;

            eG = p_curve.base.mul(rand_e);
            if (eG.x.is_zero()) {
                return null;
            }
            r = hash_v.mod_mul(eG.x);

            r = p_curve.truncate(r);
            if (r.is_zero()) {
                return null;
            }

            r = new bn.BN(r.buf8(), 8);
            big_d = new bn.BN(param_d.buf8(), 8);
            big_rand_e = new bn.BN(rand_e.buf8(), 8);
            big_order = new bn.BN(p_curve.order.buf8(), 8);
            s = big_d.mul(r).mod(big_order);
            s = s.add(big_rand_e).mod(big_order);

            return {
                "s": new Field(s.toArray(), 'buf8', p_curve),
                "r": new Field(r.toArray(), 'buf8', p_curve),
            };
        },
        sign = function (hash_buf, fmt) {
            var rand_e, ret, hash_v;

            if (Buffer.isBuffer(hash_buf)) {
                hash_v = new Field(util.add_zero(hash_buf, true), 'buf8', p_curve);
            } else {
                throw new Error("not a buffer");
            }

            if (hash_v.is_zero()) {
                throw new Error("Pass non zero value");
            }

            while (true) {
                rand_e = p_curve.rand();

                ret = help_sign(hash_v, rand_e);
                if (ret !== null) {
                    break;
                }
            }

            ret.hash = hash_v;
            if (fmt === undefined) {
                return ret;
            }
            return sign_serialise(ret, fmt);
        },
        decrypt = function(data, pubkey, param, algo) {
            if(pubkey.pubkey) {
                pubkey = pubkey.pubkey;
            }
            var kek = this.sharedKey(pubkey, param.ukm, algo.kdf);
            var cek = algo.keyunwrap(kek, param.wcek);
            return algo.decrypt(data, cek, param.iv);
        },
        encrypt = function(data, cert, algo) {
            var cek = crypto.getRandomValues(new Buffer(32)),
                ukm = crypto.getRandomValues(new Buffer(64)),
                iv = crypto.getRandomValues(new Buffer(8));

            var kek = this.sharedKey(cert.pubkey, ukm, algo.kdf);
            var wcek = algo.keywrap(kek, cek, iv);
            var ctext = algo.encrypt(data, cek, iv);
            return {
                iv: iv,
                wcek: wcek,
                data: ctext,
                ukm: ukm,
            };

        },
        pub_match = function(pub_key) {
            var check_key = null;
            if(pub_key.type === 'Pub') {
                return pub_key.point.equals(this.pub().point);
            }
            if(pub_key._is_field) {
                check_key = pub_key;
            }
            if (Buffer.isBuffer(pub_key)) {
                check_key = new Field(pub_key, 'buf8', p_curve);
            }
            if(check_key === null) {
                throw new Error("Unknow pubkey format");
            }

            return check_key.equals(this.pub_compress());
        },
        pub_compress = function () {
            if(this._pub === undefined) {
                this._pub = this.pub();
            }

            if(this._pub_cmp === undefined) {
                this._pub_cmp = this._pub.point.compress();
            }

            return this._pub_cmp;
        },
        pub = function () {
            return new Pub(p_curve, p_curve.base.mul(param_d).negate());
        },
        /*
            Diffie-Hellman key exchange proto and DSTSZI key wrapping algo
            Implementation note:

                ephemeral keys are not supported, so curves SHOULD match.
        */
        derive = function (pubkey) {
            var pointQ, pointZ, bufZZ, cut;
            if (pubkey.type === 'Pub') {
                pointQ = pubkey.point;
            } else {
                pointQ = p_curve.point(pubkey);
            }
            pointZ = pointQ.mul(param_d.mod_mul(p_curve.kofactor));
            bufZZ = new Buffer(pointZ.x.buf8(), 'raw');
            cut = bufZZ.length - Math.ceil(p_curve.m/8);
            return bufZZ.slice(cut);
        },
        /*
         * Computes key for symmetric cypher for two given parties.
         * kdf function should be passed in arguments.
         *
         * pubkey can be either 
         *  - {x, y} hash,
         *  - Pub model instance with point on same curve or
         *  - Bignum with compressed representation of key
         *                      
         * ukm (salt) should be either 32 bytes buffer or null.
         * */
        sharedKey = function (pubkey, ukm, kdf) {
            var zz, counter, salt, kek_input;

            zz = this.derive(pubkey);
            if(zz[0] === 0) {
                zz = zz.slice(1);
            }
            counter = new Buffer("\x00\x00\x00\x01");
            salt = gost_salt(ukm);

            kek_input = new Buffer(
                zz.length + counter.length + salt.length
            );
            zz.copy(kek_input);
            counter.copy(kek_input, zz.length);
            salt.copy(kek_input, zz.length + counter.length);

            return kdf(kek_input);
        },
        as_pem = function () {
            return (
                '-----BEGIN PRIVATE KEY-----\n' +
                b64_encode(this.as_asn1(), {line: 16, pad: true}) +
                '\n-----END PRIVATE KEY-----'
            );
        },
        as_asn1 = function () {
            var key = this.as_struct();
            return DstuPrivkey.encode(key, 'der');
        },
        as_struct = function () {
            var key = {
                version: 0,
                priv0: {
                    id: "DSTU_4145_LE",
                    p: {
                        p: this.curve.as_struct(),
                        sbox: dstszi2010.DEFAULT_SBOX_COMPRESSED,
                    },
                },
                param_d: param_d.le(),
                attr: []
            };
            return key;
        };

    param_d = param_d._is_field ? param_d : new jk.Field(param_d, 'bn', p_curve);

    ob = {
        'help_sign': help_sign,
        'sign': sign,
        'encrypt': encrypt,
        'decrypt': decrypt,
        'pub': pub,
        'pub_match': pub_match,
        'pub_compress': pub_compress,
        'derive': derive,
        'sharedKey': sharedKey,
        'type': 'Priv',
        "d" : param_d,
        "curve": p_curve,
        "as_struct": as_struct,
        "as_asn1": as_asn1,
        "as_pem": as_pem,
    };
    return ob;
};

var from_pem = function (data) {
    return from_asn1(pem.maybe_pem(data));
};


module.exports = Priv;
module.exports.detect_format = detect_format;
module.exports.from_asn1 = from_asn1;
module.exports.from_pem = from_pem;
module.exports.sign_serialise = sign_serialise;
