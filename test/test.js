var val_hex = 'aff3ee09cb429284985849e20de5742e194aa631490f62ba88702505629a65890',
    rv_hex = 'ff3ee09cb429284985849e20de5742e194aa631490f62ba88702505629a60895';

try {
    window.location;
    document.body;
} catch (e) {
    window = {};
    document = {
        attachEvent: function() {},
    }
}

var assert = require("assert"),
    sjcl = require('../libs/sjcl/sjcl.js'),
    Curve = require('../curve.js'),
    Field = Curve.Field,
    Priv = Curve.Priv;

describe('bn', function() {
    describe("#xor()", function() {
        it("makes a XOR b" ,function() {
            var a, b, c, expect;

            a = new sjcl.bn('100000000000000000002');
            b = new sjcl.bn('300000000000000000001');
            c = a.xor(b);
            expect = new sjcl.bn('200000000000000000003');

            assert.equal(expect.equals(c), true);
        })
    })

    describe("#lshift()", function() {
        it("shifts bignum to bit position", function() {
            var a, c, expect;

            a = new sjcl.bn('80101001');
            expect = new sjcl.bn('200404004');
            c = a.lshift(2);

            assert.equal(c.equals(expect), true);

            a = new sjcl.bn('2020201');
            expect = new sjcl.bn('1010100800000000');
            c = a.lshift(35);

            assert.equal(c.equals(expect), true);
        })
    })

    describe("#bitlength()", function() {
        it("calculates bit length", function() {
            var bn = new sjcl.bn('aff3ee09cb429284985849e20de5742e194aa631490f62ba88702505629a65890');

            assert.equal(bn.bitLength(), 260);

            bn = new sjcl.bn('002ff3ee09cb429284985849e20de5742e194aa631490f62ba88702505629a61894');
            assert.equal(bn.bitLength(), 258);
        })
    })
})

describe('Curve', function() {
    describe('#comp_modulus()', function() {
        it('should compute curve modulus', function() {
            var curve = new Curve(),
                mod_hex = "20000000000000000000000000000000000000000000000000000000000001001",
                mod = new sjcl.bn(mod_hex);

            curve.comp_modulus(257, 12, 0);
            assert.equal(true, mod.equals(curve.modulus));
            assert.equal(258, curve.modulus.bitLength());
        })
    })
    describe('#contains', function() {

        curve = new Curve();
        curve.param_a = new sjcl.bn("0");
        curve.param_b = new sjcl.bn("01CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10");

        curve.comp_modulus(257, 12, 0);
        curve.set_base(new sjcl.bn('002A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7'), new sjcl.bn('010686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF'));
        curve.order = new sjcl.bn('800000000000000000000000000000006759213AF182E987D3E17714907D470D'),
        pub_x = new sjcl.bn('00AFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A6589'),
        pub_y = new sjcl.bn('01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C');

        it("should check if point is part of curve", function() {
                var pub_q = curve.point(pub_x, pub_y);
                assert.equal(curve.contains(pub_q), true);
        })

    })

    describe("#generate()", function() {
        it("should generate new private key", function() {
            var priv, pub;

            priv = curve.keygen();
            pub = priv.pub();
            assert.equal(true, curve.contains(pub.point));
        })
    })
})

describe("Field", function() {
    var curve = new Curve;
    curve.comp_modulus(257, 12, 0);

    describe("#mod", function() {
        it("should return mod of value", function() {
            var field_a, value_a, expect_b;

            value_a = new sjcl.bn(val_hex);
            expect_b = new sjcl.bn(rv_hex);
            field_a = curve.field(value_a);
            assert.equal(true, field_a.value.equals(expect_b));
        })
    })
    
    describe("#mul", function() {
        it("should return product of two values", function() {
            var value_a, field_a, value_b, hex_b, value_c, expect_hex, expect_c;

            hex_b = '01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C';
            expect_hex = '157b8e91c8b225469821fc836045a7c09c30d9fdee54b680c8247821f8c4e3352';
            value_a = new sjcl.bn(val_hex);
            value_b = new sjcl.bn(hex_b);
            expect_c = new sjcl.bn(expect_hex);

            field_a = curve.field(value_a);
            value_c = field_a.mul(value_b);
            assert.equal(true, value_c.equals(expect_c));

        })
    })

    describe('#inv', function() {
        it("should return negative of r", function() {
            expect_r_hex = 'f5ae84d0c4dc2e7e89c670fb2083d124be50b413efb6863705bd63a5168352e0';
            value_a = new sjcl.bn(val_hex);
            field_a = curve.field(value_a);

            value_r = field_a.inv();
        })
    })
})

describe('Point', function() {
    var curve = new Curve;
    curve.comp_modulus(257, 12, 0);
    curve.param_a = new sjcl.bn("0");

    var RAND_E_HEX = '7A32849E569C8888F25DE6F69A839D75057383F473ACF559ABD3C5D683294CEB',
        PUB_X_HEX = '00AFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A6589',
        PUB_Y_HEX = '01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C';

    describe("#add", function() {
        it("should produce specific point", function() {
            var rand_e = new sjcl.bn(RAND_E_HEX),
                pub_x = new sjcl.bn(PUB_X_HEX),
                pub_y = new sjcl.bn(PUB_Y_HEX),
                pp_x = new sjcl.bn('176dbde19773dfd335665597e8d6a0ab678721a5bb7030f25dc4c48b809ef3520'),
                pp_y = new sjcl.bn('6e75301556ea5d571403086691030f024c026907c8e818b2eedd9184d12040ee'),
                pub_q, pub_2q;

                pub_q = curve.point(pub_x, pub_y);
                pub_2q = pub_q.add(pub_q)

                console.log("2q: " + pub_2q.toString());

                assert.equal(true, pub_2q.x.value.equals(pp_x))
                assert.equal(true, pub_2q.y.value.equals(pp_y))
        })
    })

    describe("#mul", function() {
        it("should produce specific point", function() {
            var rand_e = new sjcl.bn(RAND_E_HEX),
                pub_x = new sjcl.bn(PUB_X_HEX),
                pub_y = new sjcl.bn(PUB_Y_HEX),
                pp_x = new sjcl.bn('f26df77ca4c807c6b94f5c577415a1fce603a85ae7678717e16cb9a78de32d15'),
                pp_y = new sjcl.bn('1785fded2804bea15b02c4fd785fd3e98ab2435b8d78da44e195a9a088d3fc2d4'),
                pub_q, point;

                pub_q = curve.point(pub_x, pub_y);
                point = pub_q.mul(rand_e);

                console.log("pq: " + pub_q.toString());
                console.log("point: " + point.toString())
                assert.equal(true, point.x.value.equals(pp_x))
                assert.equal(true, point.y.value.equals(pp_y))
        })
    })
})

describe('Sign', function() {
    var priv_d = new sjcl.bn('2A45EAFE4CD469F811737780C57253360FBCC58E134C9A1FDCD10B0E4529A143'),
        hash_v = new sjcl.bn('6845214B63288A832A772E1FE6CB6C7D3528569E29A8B3584370FDC65F474242'),
        rand_e = new sjcl.bn('7A32849E569C8888F25DE6F69A839D75057383F473ACF559ABD3C5D683294CEB'),
        sig_s = new sjcl.bn('0CCC6816453A903A1B641DF999011177DF420D21A72236D798532AEF42E224AB'),
        sig_r = new sjcl.bn('491FA1EF75EAEF75E1F20CF3918993AB37E06005EA8E204BC009A1FA61BB0FB2'),
        pub_x = new sjcl.bn('00AFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A6589'),
        pub_y = new sjcl.bn('01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C'),
        curve;

    curve = new Curve();
    curve.param_a = new sjcl.bn("0");
    curve.comp_modulus(257, 12, 0);
    curve.set_base(new sjcl.bn('002A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7'), new sjcl.bn('010686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF', 16));
    curve.order = new sjcl.bn('800000000000000000000000000000006759213AF182E987D3E17714907D470D');

    describe("#_help_sign", function() {
        it("should sign long binary value with privkey and provided E", function() {
            var priv = new Priv(curve, priv_d), sig;
            sig = priv._help_sign(hash_v, rand_e);

            assert.equal(sig.s.toString(16), 'ccc6816453a903a1b641df999011177df420d21a72236d798532aef42e224ab')
            assert.equal(sig.r.toString(16), '491fa1ef75eaef75e1f20cf3918993ab37e06005ea8e204bc009a1fa61bb0fb2');
        })
    })

    describe("#sign", function() {
        it("should sign long binary value with privkey and generated E", function() {
            var priv = new Priv(curve, priv_d), sig;
            sig = priv.sign(hash_v);

            assert.equal(Object.keys(sig).length, 2);
        })
    })

    describe("#pub", function() {
        it("should return pubkey from priv and verify sugnature", function() {
            var priv = new Priv(curve, priv_d),
                pub = priv.pub(),
                sig, ok;

            console.log("pub: " + pub.point.toString());
            assert.equal(pub.x.value.equals(pub_x), true);
            assert.equal(pub.y.value.equals(pub_y), true);

            sig = priv._help_sign(hash_v, rand_e);
            ok = pub._help_verify(hash_v, sig.s, sig.r);
            assert.equal(ok, true);
        })
    })

})
