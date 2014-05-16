var Big = require('./big.js');

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
        "toString": toString,
        "x": field_x,
        "y": field_y,
    };
    return ob;
}

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
    };
    var ob = {
        '_help_sign': help_sign,
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
