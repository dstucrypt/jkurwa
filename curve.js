var Big = require('./3rtparty/jsbn.packed.js'),
    sjcl = require('sjcl'),
    Keycoder = require('./keycoder.js'),
    ZERO = new Big("0"),
    ONE = new Big("1");

sjcl.random.startCollectors();

var fmul = function(value_1, value_2, modulus) {
    var ret = ZERO, j, bitl_a;
    bitl_1 = value_1.bitLength();
    for(j = 0; j < bitl_1; j++ ) {
        if(value_1.testBit(j)) {
            ret = ret.xor(value_2);
        }
        value_2 = value_2.shiftLeft(1);
    }
    return fmod(ret, modulus);

},
fmod = function(val, modulus) {
    var rv, bitm_l, mask;
    if(val.compareTo(modulus) < 0) {
        return val;
    }
    rv = val;
    bitm_l = modulus.bitLength();
    while(rv.bitLength() >= bitm_l) {
        mask = modulus.shiftLeft(rv.bitLength() - bitm_l);
        rv = rv.xor(mask);
    }

    return rv;
},
finv = function(value, modulus) {
    var b, c, u, v;

    b = ONE;
    c = ZERO;
    u = fmod(value, modulus);
    v = modulus;

    while(u.bitLength() > 1) {
        j = u.bitLength() - v.bitLength();
        if(j < 0) {
            var tmp;
            tmp = u;
            u = v;
            v = tmp;

            tmp = c;
            c = b;
            b = tmp;

            j = -j;
        }

        u = u.xor(v.shiftLeft(j))
        b = b.xor(c.shiftLeft(j))
    }

    return b;
},
ftrace = function(value, modulus) {
    var rv = value;
    var bitm_l = modulus.bitLength();

    for(var idx = 1; idx <= bitm_l-2; idx++) {
        rv = fmul(rv, rv, modulus);
        rv = rv.xor(value);
    }

    return rv.intValue();
},
fsquad = function(value, modulus) {
    var ret;
    if(modulus.testBit(0)) {
        ret = fsquad_odd(value, modulus);
    }

    return fmod(ret, modulus);
},
fsquad_odd = function(value, modulus) {
    var val_a = fmod(value, modulus);
    var val_z = val_a;
    var bitl_m = modulus.bitLength();
    var range_to = (bitl_m-2)/2;
    var val_w;

    for(var idx=1; idx <= range_to; idx++) {
        val_z = fmul(val_z, val_z, modulus);
        val_z = fmul(val_z, val_z, modulus);
        val_z = val_z.xor(val_a);
    }

    val_w = fmul(val_z, val_z, modulus);
    val_w = val_w.xor(val_z, val_w);

    if(val_w.compareTo(val_a) == 0) {
        return val_z;
    }

    throw new Error("squad eq fail");
};

var Field = function(param_modulus, value, is_mod) {
    var modulus = param_modulus, value;
    mod = function(val) {
        return fmod(val, modulus);
    },
    mul = function(val) {
        return fmul(val, ob.value, modulus);
    },
    add = function(val) {
        return ob.value.xor(val);
    },
    inv = function() {
        return finv(ob.value, modulus);
    };
    var ob = {
        "mul": mul,
        "mod": mod,
        "add": add,
        "inv": inv,
        "value": value,
    }
    if(is_mod !== true)
        ob.value = mod(value);
    return ob;
}

var Point = function(p_curve, p_x, p_y) {
    var zero = ZERO,
        modulus = p_curve.modulus;

    var add = function(point_1) {
        var a, x0, x1, y0, y1, x2, y2, point_2, lbd, tmp, tmp2;

        a = p_curve.param_a;
        point_2 = new Point(p_curve, zero, zero);

        x0 = field_x.value;
        y0 = field_y.value;
        x1 = point_1.x.value;
        y1 = point_1.y.value;

        if(is_zero()) {
            return point_1;
        }

        if(point_1.is_zero()) {
            return ob;
        }

        if(x0.compareTo(x1) != 0) {
            tmp = y0.xor(y1);
            tmp2 = x0.xor(x1);
            lbd = fmul(tmp, finv(tmp2, p_curve.modulus),  p_curve.modulus);
            x2 = a.xor(fmul(lbd, lbd, p_curve.modulus));
            x2 = x2.xor(lbd)
            x2 = x2.xor(x0)
            x2 = x2.xor(x1)
        } else {
            if(y1.compareTo(y0) != 0) {
                return point_2;
            } else {
                if(x1.compareTo(zero) == 0) {
                    return point_2;
                } else {
                    lbd = x1.xor(
                            point_1.y.mul(point_1.x.inv())
                    )
                    x2 = fmul(lbd, lbd, p_curve.modulus).xor(a);
                    x2 = x2.xor(lbd);
                }
            }
        }
        y2 = fmul(lbd, x1.xor(x2), p_curve.modulus);
        y2 = y2.xor(x2);
        y2 = y2.xor(y1)

        point_2.x.value = x2
        point_2.y.value = y2

        return point_2;

    },
    mul = function(param_n) {
        var point_s = new Point(p_curve, zero, zero), cmp, point;
        cmp = param_n.compareTo(zero)
        if(cmp == 0) {
            return point_s;
        }

        if(cmp < 0) {
            param_n = param_n.negate();
            point = negate();
        } else {
            point = this;
        }

        var bitn_l = param_n.bitLength();
        for(var j = bitn_l-1; j >= 0; j--) {
            point_s = point_s.add(point_s);
            if(param_n.testBit(j)) {
                point_s = point_s.add(point);
            }
        }

        return point_s;
    },
    negate = function() {
        return new Point(p_curve, field_x.value, field_x.value.xor(field_y.value));
    },
    is_zero = function() {
        return (field_x.value.compareTo(zero) == 0) && (field_y.value.compareTo(zero) == 0)
    },
    expand = function(val) {
        var pa = p_curve.param_a;
        var pb = p_curve.param_b;

        if(val.compareTo(ZERO) == 0) {
            return {
                x: val,
                y: fmul(pb, pb, p_curve.modulus),
            }
        }

        var k = val.testBit(0);
        val = val.clearBit(0);

        var trace = ftrace(val, p_curve.modulus);
        if((trace != 0 && pa.compareTo(ZERO) == 0) || (trace == 0 && pa.compareTo(ONE))) {
            val = val.setBit(0);
        }

        var x2 = fmul(val, val, p_curve.modulus);
        var y = fmul(x2, val, p_curve.modulus);

        if(pa.compareTo(ONE) == 0) {
            y = y.xor(x2);
        }

        y = y.xor(pb);
        x2 = finv(x2, p_curve.modulus);

        y = fmul(y, x2, p_curve.modulus);
        y = fsquad(y, p_curve.modulus);

        var trace_y = ftrace(y, p_curve.modulus);

        if((k != 0 && trace_y==0) || (k==0 && trace_y!==0)) {
            y = y.add(ONE);
        }

        y = fmul(y, val, p_curve.modulus);
        return {
            x: val,
            y: y,
        }
    },
    equals = function(other) {
        return (other.x.value.compareTo(ob.x.value) == 0) && (
                other.y.value.compareTo(ob.y.value) == 0
        );
    },
    toString = function() {
        return "<Point x:"+field_x.value.toString(16)+", y:" + field_y.value.toString(16) + " >"
    };

    if(p_y === undefined) {
        var coords = expand(p_x);
        p_x = coords.x;
        p_y = coords.y;
    }

    var field_x = Field(p_curve.modulus, p_x),
        field_y = Field(p_curve.modulus, p_y);
    var ob = {
        "add": add,
        "mul": mul,
        "is_zero": is_zero,
        "negate": negate,
        "expand": expand,
        "equals": equals,
        "toString": toString,
        "x": field_x,
        "y": field_y,
    };
    return ob;
}

var Pub = function(p_curve, point_q) {
    var zero = ZERO,
    help_verify = function(hash_val, s, r) {
        if(zero.compareTo(s) == 0) {
            throw new Error("Invalid sig component S");
        }
        if(zero.compareTo(r) == 0) {
            throw new Error("Invalid sig component R");
        }

        if(p_curve.order.compareTo(s) < 0) {
            throw new Error("Invalid sig component S");
        }
        if(p_curve.order.compareTo(r) < 0) {
            throw new Error("Invalid sig component R");
        }

        var mulQ, mulS, pointR, r1;

        mulQ = point_q.mul(r);
        mulS = p_curve.base.mul(s);

        pointR = mulS.add(mulQ);
        if(pointR.is_zero()) {
            throw new Error("Invalid sig R point at infinity");
        }

        r1 = pointR.x.mul(hash_val);
        r1 = p_curve.truncate(r1);

        return r.compareTo(r1) == 0;
    },
    validate = function() {
        var pub_q = ob.point, pt;

        if(pub_q.is_zero()) {
            return false;
        }

        if(p_curve.contains(pub_q) == false) {
            return false;
        }

        pt = pub_q.mul(p_curve.order);
        if(!pt.is_zero()) {
            return false;
        }

        return true;
    };
    var ob = {
        x: point_q.x,
        y: point_q.y,
        point: point_q,
        validate: validate,
        _help_verify: help_verify
    };
    return ob;
};

var Priv = function(p_curve, param_d) {
    var field_d = new Field(p_curve.modulus, param_d, true);

    var help_sign = function(hash_v, rand_e) {
        var eG, r, s, hash_field;

        hash_field = new Field(p_curve.modulus, hash_v, true);
        eG = p_curve.base.mul(rand_e);
        if(eG.x.value.compareTo(ZERO)==0) {
            return null;
        }
        r = hash_field.mul(eG.x.value);
        r = p_curve.truncate(r);
        if(r.compareTo(ZERO) == 0) {
            return null;
        }

        s = param_d.multiply(r).mod(p_curve.order);
        s = s.add(rand_e).mod(p_curve.order);

        return {
            "s": s,
            "r": r,
        }
    },
    sign = function(hash_v) {
        var rand_e = p_curve.rand(), ret;

        while(true) {
            ret = help_sign(hash_v, rand_e);
            if(ret === null)
                continue;

            return ret;
        }

    },
    pub = function() {
        return new Pub(p_curve, p_curve.base.mul(param_d).negate());
    };
    var ob = {
        '_help_sign': help_sign,
        'sign': sign,
        'pub': pub,
    };
    return ob;
}

var Curve = function(params, param_b, m, k1, k2, base, order) {
    if(params.base === undefined) {
        params = {
            param_a: params,
            param_b: param_b,
            m: m, k1: k1, k2: k2,
            base: base,
            order: order,
        }
    }
    var modulus = ZERO,
        zero = ZERO,
    comp_modulus = function(k3, k2, k1) {
        var modulus = ZERO,
        modulus = modulus.setBit(k1);
        modulus = modulus.setBit(k2);
        modulus = modulus.setBit(k3);
        ob.modulus = modulus;
    },
    set_base = function(base_x, base_y) {
        ob.base = point(base_x, base_y);
    },
    field = function(val) {
        return new Field(ob.modulus, val);
    },
    point = function(px, py) {
        return new Point(ob, px, py);
    },
    truncate = function(value) {
        var bitl_o = ob.order.bitLength(),
            xbit = value.bitLength();

        while(bitl_o <= xbit) {
            value = value.clearBit(xbit - 1);
            xbit = value.bitLength();
        }
        return value;
    },
    contains = function(point) {
        var lh, y2;
        lh = point.x.value.xor(ob.param_a);
        lh = fmul(lh, point.x.value, ob.modulus);
        lh = lh.xor(point.y.value);
        lh = fmul(lh, point.x.value, ob.modulus);
        lh = lh.xor(ob.param_b);
        y2 = fmul(point.y.value, point.y.value, ob.modulus);
        lh = lh.xor(y2);

        return lh.compareTo(ZERO) == 0;
    },
    trace = function(value) {
        return ftrace(value, ob.modulus);
    },
    rand = function() {
        var bits, words, rand, ret, rand_word;

        while(!sjcl.random.isReady()) {
            true;
        }
        bits = ob.order.bitLength();
        words = Math.floor((bits+31) / 32);
        rand = sjcl.random.randomWords(words);
        ret = ZERO;
        sign = new Big('100000000', 16);

        for(var i=0; i< words; i++) {
            rand_word = new Big(null);
            rand_word.fromInt(rand[i]);
            if(rand[i]<0) {
                rand_word = rand_word.add(sign);
            }
            ret = ret.shiftLeft(32).or(rand_word);
        }

        return ret;
    },
    keygen = function() {
        var rand_d = ob.rand(), priv, pub;
        while(true) {
            priv = new Priv(ob, rand_d);
            pub = priv.pub();
            if(pub.validate()) {
                return priv;
            }
        }
    };

    var ob = {
        "field": field,
        "point": point,
        "comp_modulus": comp_modulus,
        "set_base": set_base,
        "modulus": modulus,
        "truncate": truncate,
        "contains": contains,
        "trace": trace,
        "rand": rand,
        "keygen": keygen,
        "order": params.order,
        "param_a": params.a,
        "param_b": params.b,
        "param_m": params.m,
    };
    ob.comp_modulus(params.m, params.k1, params.k2);
    if(params.base.value !== undefined) {
        ob.set_base(params.base)
    } else {
        ob.set_base(params.base.x, params.base.y);
    }
    return ob;
}

Curve.defined = {
    DSTU_B_257: new Curve({
        a: new Big("0", 16),
        b: new Big("01CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10", 16),

        base: {
            x: new Big('002A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7', 16),
            y: new Big('010686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF', 16)
        },

        order: new Big('800000000000000000000000000000006759213AF182E987D3E17714907D470D', 16),

        m: 257,
        k1: 12,
        k2: 0,
    })
}
module.exports = Curve
module.exports.Field = Field
module.exports.Priv = Priv
module.exports.Keycoder = Keycoder
module.exports.Big = Big
