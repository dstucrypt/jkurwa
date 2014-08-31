'use strict';

var jk = require('../curve.js'),
    util = require('../util.js'),
    Field = jk.Field,
    Big = require('../../3rtparty/jsbn.packed.js'),
    ZERO = new Big("0");

var detect_format = function (inp) {
    if (util.is_hex(inp) === true) {
        return 'hex';
    }

    throw new Error("Unknown pubkey format");
};

var Pub = function (p_curve, point_q) {
    var ob,
        help_verify = function (hash_val, s, r) {
            s = s._is_field ? s : new Field(s, 'bn', p_curve);
            r = r._is_field ? r : new Field(r, 'bn', p_curve);

            if (s.is_zero()) {
                throw new Error("Invalid sig component S");
            }
            if (r.is_zero()) {
                throw new Error("Invalid sig component R");
            }

            if (p_curve.order.less(s)) {
                throw new Error("Invalid sig component S");
            }
            if (p_curve.order.less(r) < 0) {
                throw new Error("Invalid sig component R");
            }

            var mulQ, mulS, pointR, r1;
            hash_val = hash_val._is_field ? hash_val : new Field(hash_val, 'bn', p_curve);

            mulQ = point_q.mul(r);
            mulS = p_curve.base.mul(s);

            pointR = mulS.add(mulQ);
            if (pointR.is_zero()) {
                throw new Error("Invalid sig R point at infinity");
            }

            r1 = pointR.x.mod_mul(hash_val);
            r1 = p_curve.truncate(r1);

            return r.equals(r1);
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
module.exports.detect_format = detect_format;
