/*jslint plusplus: true */
/*jslint bitwise: true */

'use strict';

var Keycoder = require('./keycoder.js'),
    base64 = require('./base64.js'),
    rfc3280 = require('./rfc3280.js'),
    dstszi2010 = require('./dstszi2010.js'),
    models = require('./lib/models/index.js'),
    gf2m = require('./lib/gf2m.js');

var Point = function (p_curve, p_x, p_y) {
    var zero = p_curve.zero(),
        modulus = p_curve.modulus,
        ob,
        coords,
        add = function (point_1) {
            var a, x0, x1, y0, y1, x2, y2, point_2, lbd, tmp, tmp2;

            a = p_curve.param_a;

            x0 = ob.x;
            y0 = ob.y;
            x1 = point_1.x;
            y1 = point_1.y;

            if (ob.is_zero()) {
                return point_1;
            }

            if (point_1.is_zero()) {
                return ob;
            }

            if (!x0.equals(x1)) {
                tmp = y0.add(y1);
                tmp2 = x0.add(x1);
                lbd = tmp.mod_mul(tmp2.invert(true, p_curve._reuse_buf));
                x2 = a.add(lbd.mod_mul(lbd, p_curve._reuse_bufx2));
                x2.addM(lbd);
                x2.addM(x0);
                x2.addM(x1);
            } else {
                if (y1.equals(y0) === false) {
                    return point_2;
                }
                if (x1.is_zero()) {
                    return point_2;
                }

                lbd = point_1.y.mod_mul(point_1.x.invert(false, p_curve._reuse_buf));
                lbd.addM(x1);
                x2 = lbd.mod_mul(lbd).add(a);
                x2.addM(lbd);
            }
            y2 = lbd.mod_mul(x1.add(x2));
            y2.addM(x2);
            y2.addM(y1);

            if(x2._is_field !== true) throw new Error();
            if(y2._is_field !== true) throw new Error();

            return p_curve.point(x2, y2);
        },
        mul = function (param_n) {
            var point_s = p_curve.Inf,
                cmp, point,
                bitn_l = param_n.bitLength(),
                j;

            if (param_n.is_zero()) {
                return point_s;
            }

            point = this;

            if (param_n.negative) {
                param_n = param_n.negate();
                point = ob.negate();
            } else {
                point = this;
            }

            for (j = bitn_l - 1; j >= 0; j--) {
                point_s = point_s.twice();
                if (param_n.testBit(j)) {
                    point_s = point_s.add(point);
                }
            }

            return point_s;
        },
        twice = function () {
            return ob.add(ob);
        },
        twicePlus = function (point_1) {
            return ob.add(ob).add(point_1);
        },
        timesPow2 = function (e) {
            var p = ob;
            while (--e >= 0)
            {
                p = p.twice();
            }
            return p;
        },
        negate = function () {
            return new Point(p_curve, ob.x, ob.x.add(ob.y));
        },
        is_zero = function () {
            return ob.x.is_zero() && ob.y.is_zero();
        },
        expand = function (val) {
            var pa = p_curve.param_a,
                pb = p_curve.param_b,
                k,
                x2,
                y,
                trace,
                trace_y;

            if (val.compareTo(ZERO) === 0) {
                return {
                    x: val,
                    y: fmul(pb, pb, modulus),
                };
            }

            k = val.testBit(0);
            val = val.clearBit(0);

            trace = ftrace(val, modulus);
            if ((trace !== 0 && pa.compareTo(ZERO) === 0) || (trace === 0 && pa.compareTo(ONE) === 0)) {
                val = val.setBit(0);
            }

            x2 = fmul(val, val, modulus);
            y = fmul(x2, val, modulus);

            if (pa.compareTo(ONE) === 0) {
                y = y.xor(x2);
            }

            y = y.xor(pb);
            x2 = finv(x2, modulus);

            y = fmul(y, x2, modulus);
            y = fsquad(y, modulus);

            trace_y = ftrace(y, modulus);

            if ((k === true && trace_y === 0) || (k === false && trace_y !== 0)) {
                y = y.xor(ONE);
            }

            y = fmul(y, val, modulus);

            return {
                x: val,
                y: y,
            };
        },
        compress = function() {
            var x_inv, tmp, ret, trace;

            x_inv = finv(ob.x.value, modulus);
            tmp = fmul(x_inv, ob.y.value, modulus);
            trace = ftrace(tmp, modulus);
            ret = ob.x.value;
            if(trace === 1) {
                ret = ret.setBit(0);
            } else {
                ret = ret.clearBit(0);
            }

            return ret;
        },
        equals = function (other) {
            return (other.x.value.compareTo(ob.x.value) === 0) && (
                other.y.value.compareTo(ob.y.value) === 0
            );
        },
        toString = function () {
            return "<Point x:" + ob.x.toString(16) + ", y:" + ob.y.toString(16) + " >";
        };

    if (p_y === undefined) {
        coords = expand(p_x);
        p_x = coords.x;
        p_y = coords.y;
    }

    ob = {
        "add": add,
        "mul": mul,
        "is_zero": is_zero,
        "negate": negate,
        "expand": expand,
        "compress": compress,
        "equals": equals,
        "twicePlus": twicePlus,
        "timesPow2": timesPow2,
        "twice": twice,
        "toString": toString,
        "x": p_x,
        "y": p_y,
        "Inf": p_curve.Inf,
    };
    return ob;
};

var Pub = function (p_curve, point_q) {
    var ob,
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
        help_verify: help_verify
    };
    return ob;
};

var Priv = function (p_curve, param_d) {
    var ob,
        help_sign = function (hash_v, rand_e) {
            var eG, r, s, hash_field;

            hash_field = p_curve.field(hash_v, 'hex');
            eG = p_curve.base.mul(rand_e);

            if (eG.x.is_zero()) {
                return null;
            }
            r = hash_field.mod_mul(eG.x);
            r = p_curve.truncate(r);
            if (r.is_zero()) {
                return null;
            }

            // convert into bn
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
            var base_mul = p_curve.base.mul(param_d);
            return new Pub(p_curve, base_mul.negate());
        };

    ob = {
        'help_sign': help_sign,
        'sign': sign,
        'pub': pub,
    };
    return ob;
};

var Curve = function (params, param_b, m, k1, k2, base, order) {
    if (params.base === undefined) {
        params = {
            a: params,
            b: param_b,
            m: m,
            ks: [m, k1, k2],
            base: base,
            order: order,
        };
    }
    var ob,
        set_base = function (base_x, base_y) {
            var x = this.field(base_x, 'hex'),
                y = base_y ? this.field(base_y, 'hex') : undefined;
            ob.base = ob.point(x, y);
        },
        field = function (val, fmt) {
            var ret = new gf2m.Field(null, null, this);
            ret.setValue(val, fmt);
            return ret;
        },
        point = function (px, py) {
            return new Point(ob, px, py);
        },
        truncate = function (value) {
            var bitl_o = ob.order.bitLength(),
                xbit = value.bitLength();

            while (bitl_o <= xbit) {
                value = value.clearBit(xbit - 1);
                xbit = value.bitLength();
            }
            return value;
        },
        contains = function (point) {
            var lh, y2;
            lh = point.x.add(ob.param_a);
            lh = lh.mod_mul(point.x);
            lh = lh.add(point.y);
            lh = lh.mod_mul(point.x);
            lh = lh.add(ob.param_b);
            y2 = point.y.mod_mul(point.y);
            lh = lh.add(y2);

            return lh.is_zero();
        },
        trace = function (value) {
            return ftrace(value, ob.modulus);
        },
        rand = function () {
            var bits, words, ret, rand24;

            rand24 = crypto.getRandomValues(this.mod_words);

            return this.field(ret);
        },
        zero = function () {
            return new gf2m.Field(new Uint32Array(this.mod_words), undefined, this);
        },
        keygen = function () {
            var rand_d = ob.rand(), priv, pub;
            while (true) {
                priv = new Priv(ob, rand_d);
                pub = priv.pub();
                if (pub.validate()) {
                    return priv;
                }
            }
        };

    var calc_modulus = function(ks) {
        var ret = new Uint32Array(this.mod_words),
            i, word, bit;

        for(i=0; i < ks.length; i++) {
            word = Math.floor(ks[i] / 32);
            bit = ks[i] % 32;
            ret[word] |= 1 << bit;
        }

        return ret;
    };

    var mod_words = Math.ceil(params.ks[0] / 32);

    ob = {
        "field": field,
        "point": point,
        "set_base": set_base,
        "truncate": truncate,
        "contains": contains,
        "trace": trace,
        "rand": rand,
        "zero": zero,
        "ks": params.ks,
        "keygen": keygen,
        "param_m": params.m,
        "Inf": null,
        "mod_words": mod_words,
        "calc_modulus": calc_modulus,
        "comp_modulus": calc_modulus,
        "_reuse_buf": new Uint32Array(mod_words*2),
        "_reuse_bufx2": new Uint32Array(mod_words + mod_words + 20),
    };
    ob.param_a = ob.field(params.a, 'hex');
    ob.param_b = ob.field(params.b, 'hex');
    ob.order = ob.field(params.order, 'hex');

    if (params.base.x === undefined) {
        ob.set_base(params.base);
    } else {
        ob.set_base(params.base.x, params.base.y);
    }

    ob.Inf = ob.point(ob.zero(), ob.zero());
    return ob;
};

Curve.defined = {
    DSTU_B_257: new Curve({
        a: "0",
        b: "01CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10",

        base: {
            x: '002A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7',
            y: '010686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF',
        },

        order: '800000000000000000000000000000006759213AF182E987D3E17714907D470D',
        m: 257,
        ks: [257, 12, 0],
    })
};

module.exports = Curve;
module.exports.Priv = Priv;
module.exports.Keycoder = Keycoder;
module.exports.b64_decode = base64.b64_decode;
module.exports.b64_encode = base64.b64_encode;
module.exports.rfc3280 = rfc3280;
module.exports.dstszi2010 = dstszi2010;
module.exports.models = models;
