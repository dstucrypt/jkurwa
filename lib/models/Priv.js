var jk = require('../curve.js'),
    dstszi2010 = require('../spec/dstszi2010.js'),
    Pub = require('./Pub.js'),
    Big = require('../../3rtparty/jsbn.packed.js'),
    ZERO = new Big("0");


var gost_salt = function(ukm) {
    return dstszi2010.SharedInfo.encode({
        "keyInfo": {
            "algorithm": "Gost28147-cfb-wrap",
            "parameters": null,
        },
        "entityInfo": ukm,
        "suppPubInfo": Buffer("\x00\x00\x01\x00"),
    }, 'der');

};


var Priv = function (p_curve, param_d) {
    var ob,
        help_sign = function (hash_v, rand_e) {
            var eG, r, s, hash_field;

            hash_field = new jk.Field(p_curve.modulus, hash_v, true);
            eG = p_curve.base.mul(rand_e);
            if (eG.x.value.compareTo(ZERO) === 0) {
                return null;
            }
            r = hash_field.mul(eG.x.value);
            r = p_curve.truncate(r);
            if (r.compareTo(ZERO) === 0) {
                return null;
            }

            s = param_d.multiply(r).mod(p_curve.order);
            s = s.add(rand_e).mod(p_curve.order);

            return {
                "s": s,
                "r": r,
            };
        },
        sign = function (hash_v) {
            var rand_e, ret;

            while (true) {
                rand_e = p_curve.rand();

                ret = help_sign(hash_v, rand_e);
                if (ret !== null) {
                    return ret;
                }
            }

        },
        pub = function () {
            return new Pub(p_curve, p_curve.base.mul(param_d).negate());
        },
        /*
            Diffie-Hellman key exchange proto and DSTSZI key wrapping algo
            Implementation note:

                ephemeral keys are not supported, so curves SHOULD match.
        */
        derive = function(pubkey) {
            var pointQ, pointZ, strZ, bufZZ, ko;
            if(pubkey.type === 'Pub') {
                pointQ = pubkey.point;
            } else {
                pointQ = p_curve.point(pubkey);
            }
            ko = p_curve.kofactor || new Big("4");
            pointZ = pointQ.mul(param_d.multiply(ko));
            strZ = pointZ.x.value.toString(16);
            bufZZ = new Buffer(strZ, 'hex');
            return bufZZ;
        },
        sharedKey = function(pubkey, ukm, kdf) {
            var zz = this.derive(pubkey),
                counter = new Buffer("\x00\x00\x00\x01"),
                salt = gost_salt(ukm);

            var kek_input = new Buffer(
                zz.length + counter.length + salt.length
            );
            zz.copy(kek_input);
            counter.copy(kek_input, zz.length);
            salt.copy(kek_input, zz.length + counter.length);

            return kdf(kek_input);
        };

    ob = {
        'help_sign': help_sign,
        'sign': sign,
        'pub': pub,
        'derive': derive,
        'sharedKey': sharedKey,
        'type': 'Priv',
    };
    return ob;
};

module.exports = Priv;
