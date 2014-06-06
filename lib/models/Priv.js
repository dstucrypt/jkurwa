var jk = require('../curve.js'),
    Pub = require('./Pub.js'),
    Big = require('../../3rtparty/jsbn.packed.js'),
    ZERO = new Big("0");


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
        };

    ob = {
        'help_sign': help_sign,
        'sign': sign,
        'pub': pub,
        'type': 'Priv',
    };
    return ob;
};

module.exports = Priv;
