var val_hex = 'aff3ee09cb429284985849e20de5742e194aa631490f62ba88702505629a65890',
    rv_hex = 'ff3ee09cb429284985849e20de5742e194aa631490f62ba88702505629a60895';

try {
    window.location;
    document.body;
} catch (e) {
    window = {};
    navigator = {};
    document = {
        attachEvent: function() {},
    }
}

var assert = require("assert"),
    Curve = require('../curve.js'),
    gf2m = require('../lib/gf2m.js'),
    Field = Curve.Field,
    Priv = Curve.Priv;


describe('Curve', function() {
    describe('#comp_modulus()', function() {
        it('should compute curve modulus', function() {
            var curve = Curve.defined.DSTU_B_257,
                mod_hex = "20000000000000000000000000000000000000000000000000000000000001001",
                mod = curve.field(mod_hex, 'hex'),
                mod2;

            mod2 = curve.comp_modulus(257, 12, 0);
            mod2 = curve.field(mod2);
            assert.equal(0, mod.equals(mod2));
            assert.equal(258, mod.bitLength());
        })
    })
    describe('#contains', function() {

        curve = Curve.defined.DSTU_B_257;
        pub_x = curve.field('00AFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A6589', 'hex'),
        pub_y = curve.field('01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C', 'hex');

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
    var curve = Curve.defined.DSTU_B_257;

    describe("#mod", function() {
        it("should return mod of value", function() {
            var field_a, value_a, expect_b;

            field_a = curve.field(val_hex, 'hex');
            expect_b = curve.field(rv_hex, 'hex');
            assert.equal(true, field_a.mod().equals(expect_b));
        })
    })
    
    describe('#inv', function() {
        it("should return negative of r", function() {
            expect_r_hex = 'f5ae84d0c4dc2e7e89c670fb2083d124be50b413efb6863705bd63a5168352e0';
            field_a = curve.field(val_hex, 'hex');

            value_r = field_a.invert();
        })
    })
})

describe('Point', function() {
    var curve = Curve.defined.DSTU_B_257;

    var RAND_E_HEX = '7A32849E569C8888F25DE6F69A839D75057383F473ACF559ABD3C5D683294CEB',
        PUB_X_HEX = '00AFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A6589',
        PUB_Y_HEX = '01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C';

    describe("#add", function() {
        it("should add point to itself", function() {
            var rand_e = curve.field(RAND_E_HEX, 'hex'),
                pub_x = curve.field(PUB_X_HEX, 'hex'),
                pub_y = curve.field(PUB_Y_HEX, 'hex'),
                pp_x = curve.field('176dbde19773dfd335665597e8d6a0ab678721a5bb7030f25dc4c48b809ef3520', 'hex'),
                pp_y = curve.field('6e75301556ea5d571403086691030f024c026907c8e818b2eedd9184d12040ee', 'hex'),
                pub_q, pub_2q;

                pub_q = curve.point(pub_x, pub_y);
                pub_2q = pub_q.add(pub_q)

                assert.equal(true, pub_2q.x.equals(pp_x))
                assert.equal(true, pub_2q.y.equals(pp_y)) 
        })
    })

    describe("#mul", function(done) {
        it("should produce specific point", function() {

            var rand_e = curve.field(RAND_E_HEX, 'hex'),
                pub_x = curve.field(PUB_X_HEX, 'hex'),
                pub_y = curve.field(PUB_Y_HEX, 'hex'),
                pp_x = curve.field('f26df77ca4c807c6b94f5c577415a1fce603a85ae7678717e16cb9a78de32d15', 'hex'),
                pp_y = curve.field('1785fded2804bea15b02c4fd785fd3e98ab2435b8d78da44e195a9a088d3fc2d4', 'hex'),
                pub_q, point;

                pub_q = curve.point(pub_x, pub_y);
                point = pub_q.mul(rand_e);

                assert.equal(true, point.x.equals(pp_x))
                assert.equal(true, point.y.equals(pp_y))
        })
    })

    describe("#trace()", function() {
        it("should compute field trace", function() {
            var value_hex = '2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6';
            var value = new Big(value_hex, 16);
            var trace = curve.trace(value);

            assert.equal(1, trace);
        })
    })

    describe("#expand()", function() {
        it("should compute coordinates from compressed point", function() {
            var pt = curve.point(ZERO, ZERO);
            var coords = pt.expand(ZERO);
            assert.equal(0, ZERO.compareTo(coords.x));

            var compressed = new Big("2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6", 16);
            var coords = pt.expand(compressed);

            assert.equal(0, coords.x.compareTo(curve.base.x.value));
            assert.equal(0, coords.y.compareTo(curve.base.y.value));

            var pt = curve.point(compressed);

            assert.equal(true, pt.equals(curve.base));
        })

        it("should check tax office pubkey decompression", function() {
            var compressed = new Big("01A77131A7C14F9AA6EA8C760D39673D5F0330FAB1118D55B55B7AF0735975485F", 16);
            var pt = curve.point(compressed);
            var expect_pt = curve.point(
                new Big("01A77131A7C14F9AA6EA8C760D39673D5F0330FAB1118D55B55B7AF0735975485F", 16),
                new Big("DC058ADA665D99084038B5F914FB9CF7214760A4865B49CAF7F4BE7379F3A395", 16)
            );

            assert.equal(true, pt.equals(expect_pt));

            compressed = new Big("2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6", 16);
            var pt = curve.point(compressed);
            var expect_pt = curve.point(
                new Big("2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7", 16),
                new Big("010686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF", 16)
            );

            assert.equal(true, pt.equals(expect_pt));
        })
    })

    describe("#compress()", function() {
        it("should compress point coords", function() {
            var pt = curve.base;
            var compressed = pt.compress();

            var expected = new Big("2a29ef207d0e9b6c55cd260b306c7e007ac491ca1b10c62334a9e8dcd8d20fb6", 16);

            assert.equal(0, compressed.compareTo(expected));
        })
    })

})

describe('Sign', function() {
    var curve = Curve.defined.DSTU_B_257,
        priv_d = curve.field('2A45EAFE4CD469F811737780C57253360FBCC58E134C9A1FDCD10B0E4529A143', 'hex'),
        hash_v ='6845214B63288A832A772E1FE6CB6C7D3528569E29A8B3584370FDC65F474242',
        rand_e = curve.field('7A32849E569C8888F25DE6F69A839D75057383F473ACF559ABD3C5D683294CEB', 'hex'),
        sig_s = curve.field('0CCC6816453A903A1B641DF999011177DF420D21A72236D798532AEF42E224AB', 'hex'),
        sig_r = curve.field('491FA1EF75EAEF75E1F20CF3918993AB37E06005EA8E204BC009A1FA61BB0FB2', 'hex'),
        pub_x = curve.field('00AFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A6589', 'hex'),
        pub_y = curve.field('01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C', 'hex'),
        curve;

    curve = Curve.defined.DSTU_B_257;

    describe("#help_sign", function() {
        it("should sign long binary value with privkey and provided E", function() {
            var priv = new Priv(curve, priv_d), sig;
            sig = priv.help_sign(hash_v, rand_e);

            assert.equal(sig.s.toString(16), 'ccc6816453a903a1b641df999011177df420d21a72236d798532aef42e224ab')
            assert.equal(sig.r.toString(16), '491fa1ef75eaef75e1f20cf3918993ab37e06005ea8e204bc009a1fa61bb0fb2');
        })
    }) 

    describe("#help_verify", function() {
        it("should verify signed value with pubkey", function() {
            var sig = {
            }

            sig = priv.help_sign(hash_v, rand_e);
            ok = pub.help_verify(hash_v, sig.s, sig.r);
            assert.equal(ok, true);

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
        it("should return pubkey from priv", function() {
            var priv = new Priv(curve, priv_d),
                pub = priv.pub(),
                sig, ok;

            assert.equal(pub.x.equals(pub_x), true);
            assert.equal(pub.y.equals(pub_y), true);
        })
    })

})

describe('Known value', function() {
    var curve = Curve.defined.DSTU_B_257;

    describe("#expand()", function() {
        it("should compute coordinates from compressed point", function() {
            var compressed = curve.field("76cd4555ad63455529755e5c3f3066c3bcb957cc63d00e22c6dd1e9ed316b419", 'hex');
            var pt = curve.zero();

            var coords = pt.expand(compressed);

            var px = new Big('76cd4555ad63455529755e5c3f3066c3bcb957cc63d00e22c6dd1e9ed316b418', 16);
            var py = new Big('12b20103548f45dcbed5486022dfcb244b2d996e0d3d761abaf73ba16ea26e0d3', 16);

            assert.equal(0, coords.x.compareTo(px));
            assert.equal(0, coords.y.compareTo(py));
        })
    })

})
