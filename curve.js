var Big = require('./big.js');

var Field = function(param_modulus, value) {
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
    ob.value = mod(value);
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
    field = function(val) {
        return new Field(ob.modulus, val);
    };
    var ob = {
        "field": field,
        "comp_modulus": comp_modulus,
        "modulus": modulus,
    };
    return ob;
}

module.exports = Curve
module.exports.Field = Field
