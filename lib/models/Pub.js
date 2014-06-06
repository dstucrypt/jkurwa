var jk = require('../curve.js'),
    Field = jk.Field,
    Big = require('../../3rtparty/jsbn.packed.js'),
    ZERO = new Big("0");

var Pub = function (p_curve, point_q) {
    var zero = ZERO,
        ob,
        help_verify = function (hash_val, s, r) {
            if (zero.compareTo(s) === 0) {
                throw new Error("Invalid sig component S");
            }
            if (zero.compareTo(r) === 0) {
                throw new Error("Invalid sig component R");
            }

            if (p_curve.order.compareTo(s) < 0) {
                throw new Error("Invalid sig component S");
            }
            if (p_curve.order.compareTo(r) < 0) {
                throw new Error("Invalid sig component R");
            }

            var mulQ, mulS, pointR, r1;

            mulQ = point_q.mul(r);
            mulS = p_curve.base.mul(s);

            pointR = mulS.add(mulQ);
            if (pointR.is_zero()) {
                throw new Error("Invalid sig R point at infinity");
            }

            r1 = pointR.x.mul(hash_val);
            r1 = p_curve.truncate(r1);

            return r.compareTo(r1) === 0;
        },
        validate = function () {
            var pub_q = ob.point, pt;

            if (pub_q.is_zero()) {
                return false;
            }

            if (p_curve.contains(pub_q) === false) {
                return false;
            }

            pt = pub_q.mul(p_curve.order);
            if (!pt.is_zero()) {
                return false;
            }

            return true;
        };
    ob = {
        x: point_q.x,
        y: point_q.y,
        point: point_q,
        validate: validate,
        help_verify: help_verify,
        type: 'Pub',
    };
    return ob;
};

module.exports = Pub;
