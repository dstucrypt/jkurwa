'use strict';

var jk = require('../curve.js'),
    util = require('../util.js'),
    Field = jk.Field;

var detect_format = function (inp) {
    if (util.is_hex(inp) === true) {
        return 'hex';
    }
    if(inp.buffer !== undefined) {
        return 'raw';
    }

    throw new Error("Unknown pubkey format");
};


var detect_sign_format = function(sign) {
    if (sign.hasOwnProperty && sign.hasOwnProperty('s') && sign.hasOwnProperty('r')) {
        return 'split';
    }
    if ((typeof sign) === 'string' || Buffer.isBuffer(sign)) {
        return 'short';
    }

}


var parse_sign = function(sign, fmt, curve) {
    if (fmt == 'short') {
        if(!Buffer.isBuffer(sign)) {
            sign = Buffer(sign);
        }

        if(sign[0] !== 4 || sign[1] !== (sign.length - 2)) {
            throw Error("Broken short sign");
        }

        var r = sign.slice(2, Math.ceil(sign[1] / 2) + 2),
            s = sign.slice(2 + r.length);

        sign = {
            s: util.add_zero(s, true),
            r: util.add_zero(r, true),
        };
        fmt = 'split';
    }

    if (fmt === 'split') {
        if((typeof sign.s) === 'string') {
            sign.s = Buffer(sig.s);
        }
        if((typeof sign.r) === 'string') {
            sign.r = Buffer(sig.r);
        }

        return {
            s: new Field(sign.s, 'buf8', curve),
            r: new Field(sign.r, 'buf8', curve),

        }
    }

};

var Pub = function (p_curve, point_q, compressed) {
    var ob,
        compress = function() {
            if(!this._cmp) {
                this._cmp = point_q.compress();
            }
            return this._cmp;
        },
        verify = function (hash_val, sign, fmt) {
            if(fmt === undefined) {
                fmt = detect_sign_format(sign);
            }
            if(Buffer.isBuffer(hash_val)) {
                hash_val = new Field(util.add_zero(hash_val, true), 'buf8', p_curve);
            }

            sign = parse_sign(sign, fmt, p_curve);
            return this.help_verify(hash_val, sign.s, sign.r);
        },
        help_verify = function (hash_val, s, r) {
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
        compress: compress,
        _cmp: compressed,
        validate: validate,
        help_verify: help_verify,
        verify: verify,
        type: 'Pub',
    };
    return ob;
};

module.exports = Pub;
module.exports.detect_format = detect_format;
module.exports.parse_sign = parse_sign;
