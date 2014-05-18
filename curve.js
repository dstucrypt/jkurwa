var sjcl = require('./libs/sjcl/sjcl.js'),
    ZERO = new sjcl.bn(0),
    ONE = new sjcl.bn(1);

sjcl.random.startCollectors();

var fmul = function(value_1, value_2, modulus) {
    var ret = ZERO.copy(), j, bitl_1;
    bitl_1 = value_1.bitLength();
    value_2 = value_2.copy();
    for(j = 0; j < bitl_1; j++ ) {
        if(value_1.testBit(j)) {
            ret.xorM(value_2);
        }
        value_2.lshiftM(1);
    }
    return fmod(ret, modulus);

},
fmod = function(val, modulus) {
    var rv, bitm_l, mask;

    val.greaterEquals(val)
    if(modulus.greaterEquals(val) == 1) {
        return val.copy();
    }
    rv = val.copy();
    bitm_l = modulus.bitLength();
    while(rv.bitLength() >= bitm_l) {
        mask = modulus.lshift(rv.bitLength() - bitm_l);
        rv.xorM(mask);
    }

    rv.trim();
    return rv;
},
finv = function(value, modulus) {
    var b, c, u, v;

    b = ONE.copy();
    c = ZERO.copy();
    u = fmod(value, modulus);
    v = modulus.copy();

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

        u = u.xorM(v.lshift(j))
        b = b.xorM(c.lshift(j))
    }

    b.trim();
    return b;
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
    var field_x = Field(p_curve.modulus, p_x),
        field_y = Field(p_curve.modulus, p_y),
        zero = ZERO,
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

        if(x0.equals(x1) == false) {
            tmp = y0.xor(y1);
            tmp2 = x0.xor(x1);
            lbd = fmul(tmp, finv(tmp2, p_curve.modulus),  p_curve.modulus);
            lbd.trim();
            x2 = a.xor(fmul(lbd, lbd, p_curve.modulus));
            x2.xorM(lbd)
            x2.xorM(x0)
            x2.xorM(x1)
        } else {
            if(y1.equals(y0) == false) {
                return point_2;
            } else {
                if(x1.equals(zero) == true) {
                    return point_2;
                } else {
                    lbd = x1.xor(
                            point_1.y.mul(point_1.x.inv())
                    )
                    x2 = fmul(lbd, lbd, p_curve.modulus).xor(a);
                    x2.xorM(lbd);
                    x2.trim();
                    lbd.trim();
                }
            }
        }
        y2 = fmul(lbd, x1.xor(x2), p_curve.modulus);
        y2 = y2.xor(x2);
        y2 = y2.xor(y1);
        y2.trim();

        point_2.x.value = x2
        point_2.y.value = y2

        return point_2;

    },
    mul = function(param_n) {
        var point_s = new Point(p_curve, zero, zero), cmp, point;
        if(param_n.equals(zero)) {
            return point_s;
        }

        if(zero.greaterEquals(param_n)) {
            param_n = param_n.mul(-1);
            point = negate();
        } else {
            point = this;
        }

        var bitn_l = param_n.bitLength(), radix = param_n.radix;

        for(var l = param_n.limbs.length-1; l >= 0; l--) {
            var ln = param_n.limbs[l], b = radix-1;

            for(; b >= 0; b--) {
                point_s = point_s.add(point_s);
                if(ln & (1<<b)) {
                    point_s = point_s.add(point);
                }
            }
        }

        return point_s;
    },
    negate = function() {
        return new Point(p_curve, field_x.value, field_x.value.xor(field_y.value));
    },
    is_zero = function() {
        return (field_x.value.equals(zero) && field_y.value.equals(zero))
    },
    toString = function() {
        return "<Point x:"+field_x.value.toString(16)+", y:" + field_y.value.toString(16) + " >"
    };

    var ob = {
        "add": add,
        "mul": mul,
        "is_zero": is_zero,
        "negate": negate,
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
        if(eG.x.value.equals(ZERO)) {
            return null;
        }
        r = hash_field.mul(eG.x.value);
        r = p_curve.truncate(r);
        if(r.equals(ZERO)) {
            return null;
        }

        s = param_d.mulmod(r, p_curve.order);
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
        "param_d": param_d,
    };
    return ob;
}

var Curve = function() {
    var modulus = ZERO,
        zero = ZERO,
    comp_modulus = function(k3, k2, k1) {
        var modulus = ZERO.copy();
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
        lh = lh.xorM(point.y.value);
        lh = fmul(lh, point.x.value, ob.modulus);
        lh = lh.xorM(ob.param_b);

        y2 = fmul(point.y.value, point.y.value, ob.modulus);
        lh = lh.xorM(y2);

        return lh.equals(ZERO);
    },
    rand = function() {
        var bits, words, rand, ret, rand_word;

        while(!sjcl.random.isReady()) {
            true;
        }
        bits = ob.order.bitLength();
        words = Math.floor((bits+ZERO.radix-1) / ZERO.radix);
        rand = sjcl.random.randomWords(words);
        ret = ZERO.copy();
        ret.limbs = [];
        sign = 0x100000000;

        for(var i=0; i< words; i++) {
            if(rand[i] < 0) {
                ret.limbs.push(rand[i] + sign);
            } else {
                ret.limbs.push(rand[i])
            }
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
        "rand": rand,
        "keygen": keygen,
    };
    return ob;
}

module.exports = Curve
module.exports.Field = Field
module.exports.Priv = Priv
