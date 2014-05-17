var Big = require('./big.js'),
    sjcl = require('./libs/sjcl/sjcl.js');

sjcl.random.startCollectors();

var Field = function(param_modulus, value, is_mod) {
    var modulus = param_modulus, value;
    mod = function(val) {
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
    mul = function(val) {
        var ret = new Big("0"), j, bitl_a;
        bitl_a = ob.value.bitLength();
        for(j = 0; j < bitl_a; j++ ) {
            if(ob.value.testBit(j)) {
                ret = ret.xor(val);
            }
            val = val.shiftLeft(1);
        }
        return ob.mod(ret);
    },
    add = function(val) {
        return ob.value.xor(val);
    },
    inv = function() {
        var b, c, u, v;

        b = new Big("1");
        c = new Big("0");
        u = mod(ob.value);
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
        zero = new Big("0"),
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
            tmp = new Field(p_curve.modulus, y0.xor(y1), true);
            tmp2 = new Field(p_curve.modulus, x0.xor(x1), true);
            lbd = tmp.mul(tmp2.inv())
            lbd = new Field(p_curve.modulus, lbd, true)
            x2 = a.xor(lbd.mul(lbd.value))
            x2 = x2.xor(lbd.value)
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
                    lbd = new Field(modulus, lbd, true)
                    x2 = lbd.mul(lbd.value).xor(a);
                    x2 = x2.xor(lbd.value);
                }
            }
        }
        y2 = lbd.mul(x1.xor(x2));
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
    var zero = new Big("0"),
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
    };
    var ob = {
        x: point_q.x,
        y: point_q.y,
        point: point_q,
        _help_verify: help_verify
    };
    return ob;
};

var Priv = function(p_curve, param_d) {
    var field_d = new Field(p_curve.modulus, param_d, true);

    var help_sign = function(hash_v, rand_e) {
        var eG, r, s, hash_field;

        hash_field = new Field(p_curve.modulus, hash_v, true);
        eg = p_curve.base.mul(rand_e);
        r = hash_field.mul(eg.x.value);
        r = p_curve.truncate(r);

        s = param_d.multiply(r).mod(p_curve.order);
        s = s.add(rand_e).mod(p_curve.order);

        return {
            "s": s,
            "r": r,
        }
    },
    sign = function(hash_v) {
        var bits, words, rand, rand_e, rand_word, sign;

        while(!sjcl.random.isReady()) {
            true;
        }
        bits = p_curve.order.bitLength();
        words = Math.floor((bits+31) / 32);
        rand = sjcl.random.randomWords(words);
        rand_e = new Big('0');
        sign = new Big('100000000', 16);

        for(var i=0; i< words; i++) {
            rand_word = new Big(null);
            rand_word.fromInt(rand[i]);
            if(rand[i]<0) {
                rand_word = rand_word.add(sign);
            }
            rand_e = rand_e.shiftLeft(32).or(rand_word);
        }

        return help_sign(hash_v, rand_e);

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

var Curve = function() {
    var modulus = new Big("0"),
    comp_modulus = function(k3, k2, k1) {
        var modulus = new Big("0");
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
    };

    var ob = {
        "field": field,
        "point": point,
        "comp_modulus": comp_modulus,
        "set_base": set_base,
        "modulus": modulus,
        "truncate": truncate,
    };
    return ob;
}

module.exports = Curve
module.exports.Field = Field
module.exports.Priv = Priv
