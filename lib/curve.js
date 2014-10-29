/*jslint plusplus: true */
/*jslint bitwise: true */

'use strict';

var Field = require('./gf2m.js').Field,
    wnaf = require('./wnaf/index.js'),
    models = require('./models/index.js'),
    standard = require('./standard.js'),
    util = require('./util.js'),
    H = util.maybeHex;


var fsquad_odd = function (value, curve) {
    var val_a = value.mod(),
        val_z = val_a,
        bitl_m = curve.m,
        range_to = (bitl_m - 1) / 2,
        val_w,
        idx;

    for (idx = 1; idx <= range_to; idx++) {
        val_z = val_z.mod_sqr().mod_sqr();
        val_z.addM(val_a);
    }

    val_w = val_z.mod_mul(val_z);
    val_w.addM(val_z);

    if (val_w.equals(val_a)) {
        return val_z;
    }

    throw new Error("squad eq fail");
};
var fsquad = function (value, curve) {
    var ret;
    if (curve.modulus.testBit(0)) {
        ret = fsquad_odd(value, curve);
    } else {
        throw new Error("only odd modulus is supported :(");
    }

    return ret.mod();
};


var std_curve = function (curve_name) {
    var curve;

    curve = standard.cache[curve_name];
    if (curve !== undefined) {
        return curve;
    }

    curve = standard[curve_name];
    if (curve === undefined) {
        throw new Error("Curve with such name was not defined");
    }
    curve = new Curve(curve);
    standard.cache[curve_name] = curve;

    return curve;
};


var pubkey = function (curve_name, key_data, key_fmt) {
    var curve;
    curve = std_curve(curve_name);
    return curve.pubkey(key_data, key_fmt);
};


var pkey = function (curve_name, key_data, key_fmt) {
    var curve;
    curve = std_curve(curve_name);
    return curve.pkey(key_data, key_fmt);
};


var Point = function (p_curve, p_x, p_y) {
    var zero = p_curve.zero,
        ob,
        coords,
        add = function (point_1) {
            var a, x0, x1, y0, y1, x2, y2, point_2, lbd, tmp, tmp2;

            a = p_curve.param_a;
            point_2 = new Point(p_curve, zero, zero);

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

            if (x0.equals(x1) === false) {
                tmp = y0.add(y1);
                tmp2 = x0.add(x1);
                lbd = tmp.mod_mul(tmp2.invert());
                x2 = a.add(lbd.mod_mul(lbd));
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

                lbd = x1.add(point_1.y.mod_mul(point_1.x.invert()));
                x2 = lbd.mod_mul(lbd).add(a);
                x2.addM(lbd);
            }
            y2 = lbd.mod_mul(x1.add(x2));
            y2.addM(x2);
            y2.addM(y1);

            point_2.x = x2;
            point_2.y = y2;

            return point_2;

        },
        twice = function () {
            return this.add(this);
        },
        timesPow2 = function (n) {
            var ret = this;
            while(n--) {
                ret = ret.twice();
            }

            return ret;
        },
        twicePlus = function (other) {
            return this.twice().add(other);
        },
        mul = function (param_n) {
            var point_s = new Point(p_curve, zero, zero), point;

            if(param_n.is_zero()) {
                return point_s;
            }

            if (param_n.is_negative()) {
                param_n = param_n.negate();
                point = ob.negate();
            } else {
                point = this;
            }

            return wnaf.mulPos(point, param_n);
        },
        negate = function () {
            return new Point(p_curve, ob.x, ob.x.add(ob.y));
        },
        is_zero = function () {
            return (ob.x.is_zero() && ob.y.is_zero());
        },
        expand = function (val) {
            return p_curve.expand(val);
        },
        compress = function () {
            var x_inv, tmp, ret, trace;

            x_inv = ob.x.invert();
            tmp = x_inv.mod_mul(ob.y);
            trace = tmp.trace();
            ret = ob.x;
            if (trace === 1) {
                ret = ret.setBit(0);
            } else {
                ret = ret.clearBit(0);
            }

            return ret;
        },
        equals = function (other) {
            return other.x.equals(ob.x) && other.y.equals(ob.y);
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
        "twice": twice,
        "timesPow2": timesPow2,
        "twicePlus": twicePlus,
        "mul": mul,
        "is_zero": is_zero,
        "negate": negate,
        "expand": expand,
        "compress": compress,
        "equals": equals,
        "toString": toString,
        "x": p_x._is_field ? p_x : new Field(p_x, 'buf32', p_curve),
        "y": p_y._is_field ? p_y : new Field(p_y, 'buf32', p_curve),
        "_precomp" : {pos: [], neg: []},
    };
    ob._precomp.pos[0] = ob;
    return ob;
};


var ks_parse = function (ks) {
    if (ks.type === 'trinominal') {
        return [ks.value];
    }
    return [ks.value.k1, ks.value.k2, ks.value.k3];
};


var from_asn1 = function(curve, fmt) {
    var big = (fmt === 'cert') ? util.BIG_LE : util.BIG_BE;

    return new Curve({
        m: curve.p.param_m,
        ks: ks_parse(curve.p.ks),
        a: [curve.param_a],
        b: big(curve.param_b),
        order: util.BIG_BE(curve.order.toArray()),
        kofactor: [4],
        base: big(curve.bp),
    });
};


var Curve = function (params, param_b, m, ks, base, order, kofactor) {
    if (params.base === undefined) {
        params = {
            param_a: params,
            param_b: param_b,
            m: m,
            ks: ks,
            base: base,
            order: order,
            kofactor: kofactor,
        };
    }
    var ob,
        expand_cache = {},
        comp_modulus = function (m, ks) {
            var modulus = ob.one, i;
            modulus = modulus.setBit(m);
            for (i = 0; i < ks.length; i++) {
                modulus = modulus.setBit(ks[i]);
            }
            return modulus;
        },
        set_base = function (base_x, base_y) {
            var cmp, width;
            width = wnaf.getWindowSize(ob.m);
            width = Math.max(2, Math.min(16, width));
            ob.base = ob.point(base_x, base_y);
            wnaf.precomp(ob.base, width);
            cmp = ob.base.compress();
            expand_cache[cmp.toString()] = ob.base;
        },
        expand = function (val) {
            var pa = ob.param_a,
                pb = ob.param_b,
                x2,
                y,
                k,
                cached,
                trace,
                trace_y;

            if((typeof val) === 'string') {
                val = new Field(val, 'hex', this);
            }
            val = val._is_field ? val : new Field(val, 'buf32', ob);

            if (val.is_zero()) {
                return {
                    x: val,
                    y: pb.mod_mul(pb),
                };
            }

            cached = expand_cache[val.toString()];
            if (cached !== undefined) {
                return cached;
            }

            k = val.testBit(0);
            val = val.clearBit(0);

            trace = val.trace();
            if ((trace !== 0 && pa.is_zero()) || (trace === 0 && pa.equals(this.one))) {
                val = val.setBit(0);
            }

            x2 = val.mod_mul(val);
            y = x2.mod_mul(val);

            if (pa.equals(this.one)) {
                y.addM(x2);
            }

            y.addM(pb);
            x2 = x2.invert();

            y = y.mod_mul(x2);
            y = fsquad(y, this);

            trace_y = y.trace();

            if ((k === true && trace_y === 0) || (k === false && trace_y !== 0)) {
                y.bytes[0] ^= 1;
            }

            y = y.mod_mul(val);

            return {
                x: val,
                y: y,
            };

        },
        field = function (val) {
            return new Field(val.bytes, undefined, this).mod();
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
            lh.addM(point.y);
            lh = lh.mod_mul(point.x);
            lh.addM(ob.param_b);
            y2 = point.y.mod_mul(point.y);
            lh.addM(y2);

            return lh.is_zero();
        },
        rand = function () {
            var bits, words, ret, rand32;

            bits = ob.order.bitLength();
            words = Math.ceil(bits / 32);
            rand32 = new Uint32Array(words);
            rand32 = crypto.getRandomValues(rand32);

            ret = new Field(rand32, undefined, this);

            return ret;
        },
        pkey = function (inp, fmt) {
            var param_d;
            if (fmt === undefined) {
                fmt = models.Priv.detect_format(inp);
            }

            if (fmt === 'hex') {
                param_d = new Field(inp, 'hex', ob);
                return new models.Priv(ob, param_d);
            }
            if (fmt === 'bignum') {
                return new models.Priv(ob, inp);
            }
            if ((fmt === 'buf8') || (fmt === 'buf32')) {
                return new models.Priv(ob, new Field(inp, fmt, ob));
            }
        },
        pubkey = function (inp, fmt) {
            var pointQ;
            if (fmt === undefined) {
                fmt = models.Pub.detect_format(inp);
            }

            if (fmt === 'hex') {
                inp = new Field(inp, 'hex', this);
                fmt = 'field';
            }

            if(fmt === 'raw') {
                inp = new Field(inp, 'buf32', this);
                fmt = 'field';
            }

            pointQ = ob.point(inp);
            return new models.Pub(ob, pointQ, inp);
        },
        equals = function (other) {
            var i, attr, for_check = [
                'a', 'b', 'order', 'modulus',
            ];
            for (i = 0; i < for_check.length; i++) {
                attr = for_check[i];
                if (!this[attr].equals(other[attr])) {
                    return false;
                }

            }

            return this.base.equals(other.base);
        },
        keygen = function () {
            var rand_d = ob.rand(), priv, pub;
            while (true) {
                priv = new models.Priv(ob, rand_d);
                pub = priv.pub();
                if (pub.validate()) {
                    return priv;
                }
            }
        };

    var calc_modulus = function() {
        var ret = new Uint32Array(this.mod_words),
            i, word, bit;

        ret[0] = 1;
        word = Math.floor(this.m / 32);
        bit = this.m % 32;
        ret[word] |= 1 << bit;

        for(i=0; i < this.ks.length; i++) {
            word = Math.floor(this.ks[i] / 32);
            bit = this.ks[i] % 32;
            ret[word] |= 1 << bit;
        }

        return ret;
    };

    var curve_id = function() {
        return {
            163: 0,
            167: 1,
            173: 2,
            179: 3,
            191: 4,
            233: 5,
            257: 6,
            307: 7,
            367: 8,
            431: 9,
        }[this.m] || 0xFF;
    };

    var mod_words = Math.ceil(params.m / 32);

    ob = {
        "field": field,
        "point": point,
        "comp_modulus": comp_modulus,
        "expand_cache": expand_cache,
        "set_base": set_base,
        "expand": expand,
        "truncate": truncate,
        "contains": contains,
        "rand": rand,
        "keygen": keygen,
        "pkey": pkey,
        "pubkey": pubkey,
        "equals": equals,
        "order": H(params.order),
        "kofactor": params.kofactor,
        "param_a": H(params.a),
        "param_b": H(params.b),
        "param_m": params.m,
        "m": params.m,
        "ks": params.ks,
        "mod_words": mod_words,
        "calc_modulus": calc_modulus,
        "curve_id": curve_id,
    };

    ob.zero = new Field([0], 'buf32', ob);
    ob.one = new Field('1', 'hex', ob);
    ob.modulus = ob.comp_modulus(params.m, params.ks);
    ob.mod_bits = [ob.m].concat(ob.ks);
    ob.param_a = new Field(ob.param_a, 'buf32', ob);
    ob.param_b = new Field(ob.param_b, 'buf32', ob);
    ob.a = ob.param_a;
    ob.b = ob.param_b;
    ob.order = new Field(ob.order, 'buf32', ob);

    if (params.base.x === undefined) {
        params.base = ob.expand(H(params.base));
    } else {
        params.base.x = H(params.base.x);
        params.base.y = H(params.base.y);
    }
    ob.set_base(params.base.x, params.base.y);
    return ob;
};

Curve.from_asn1 = from_asn1;
Curve.ks_parse = ks_parse;
module.exports.Curve = Curve;
module.exports.Field = Field;
module.exports.pkey = pkey;
module.exports.pubkey = pubkey;
module.exports.std_curve = std_curve;
