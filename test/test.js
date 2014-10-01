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

try {
    crypto.getRandomValues;
} catch (e) {
    crypto = {
        // Moch random only for testing purposes.
        // SHOULD NOT BE USED IN REAL CODE.
        getRandomValues: function (buf) {
            var i;
            for(i=0; i < buf.length; i++) {
                buf[i] = Math.random() * 255;
                buf[i] |= (Math.random() * 255) << 8;
                buf[i] |= (Math.random() * 255) << 16;
                buf[i] |= (Math.random() * 255) << 24;
            }

            return buf;
        }
    }
}

var assert = require("assert"),
    jk = require('../lib/index.js'),
    gf2m = require('../lib/gf2m.js'),
    Curve = jk.Curve,
    Field = jk.Field,
    Priv = jk.Priv,
    Pub = jk.Pub;


describe('Curve', function() {
    describe('#comp_modulus()', function() {
        it('should compute curve modulus', function() {
            var curve = jk.std_curve('DSTU_PB_257'),
                mod_hex = "20000000000000000000000000000000000000000000000000000000000001001",
                mod = new Field(mod_hex, 'hex', curve),
                modulus;

            modulus = curve.comp_modulus(257, [12, 0]);
            assert.equal(mod.equals(modulus), true);
            assert.equal(curve.modulus.bitLength(), 258);
        })

        it('should not change modulus value on curve', function() {
            var curve = jk.std_curve('DSTU_PB_257'),
                mod_hex = "20000000000000000000000000000000000000000000000000000000000001003",
                mod = new Field(mod_hex, 'hex', curve),
                mod_before,
                modulus;

            mod_before = curve.modulus;
            modulus = curve.comp_modulus(257, [12, 1]);

            assert.equal(true, mod.equals(modulus));
            assert.equal(258, curve.modulus.bitLength());
            assert.equal(mod_before.equals(curve.modulus), true);
            assert.equal(mod.equals(curve.modulus), false);

        })
    })
    describe('#contains', function() {

        var curve = jk.std_curve('DSTU_PB_257'),
        pub_x = new Field('00AFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A6589', 'hex', curve),
        pub_y = new Field('01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C', 'hex', curve);

        it("should check if point is part of curve", function() {
                var pub_q = curve.point(pub_x, pub_y);
                assert.equal(curve.contains(pub_q), true);
        })

    })

    describe("#generate()", function() {
        it("should generate new private key", function() {
            var priv, pub, curve;

            curve = jk.std_curve('DSTU_PB_257');

            priv = curve.keygen();
            pub = priv.pub();
            assert.equal(true, curve.contains(pub.point));
        })
    })
})

describe("Field", function() {
    var curve = jk.std_curve('DSTU_PB_257');

    describe("#mod", function() {
        it("should return mod of value", function() {
            var field_a, value_a, expect_b;

            value_a = new Field(val_hex, 'hex', curve);
            expect_b = new Field(rv_hex, 'hex', curve);
            field_a = curve.field(value_a);
            assert.equal(true, field_a.equals(expect_b));
        })
    })
    
    describe("#mul", function() {
        it("should return product of two values", function() {
            var value_a, field_a, value_b, hex_b, value_c, expect_hex, expect_c;

            hex_b = '01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C';
            expect_hex = '157b8e91c8b225469821fc836045a7c09c30d9fdee54b680c8247821f8c4e3352';
            value_a = new Field(val_hex, 'hex', curve);
            value_b = new Field(hex_b, 'hex', curve);
            expect_c = new Field(expect_hex, 'hex', curve);

            field_a = curve.field(value_a);
            value_c = field_a.mod_mul(value_b);

            assert.equal(true, value_c.equals(expect_c));

        })
    })

    describe('#inv', function() {
        it("should return negative of r", function() {
            expect_r_hex = 'f5ae84d0c4dc2e7e89c670fb2083d124be50b413efb6863705bd63a5168352e0';
            value_a = new Field(val_hex, 'hex', curve);
            expect_r = new Field(expect_r_hex, 'hex', curve);
            field_a = curve.field(value_a);

            value_r = field_a.invert();

            assert.equal(true, value_r.equals(expect_r));
        })
    })

    describe('#shiftRightM', function (bits) {
        it("should bitshift big integer rightwise inplace", function () {
            var initial = new Field('7a32849e569c8888f25de6f69a839d75057383f473acf559abd3c5d683294ceb', 'hex', curve);
            var expect = new Field('3d19424f2b4e4444792ef37b4d41ceba82b9c1fa39d67aacd5e9e2eb4194a67', 'hex', curve);
            initial.shiftRightM(5);

            assert.equal(initial.equals(expect), true);
        })
    })
})

describe('Point', function() {
    var curve = jk.std_curve('DSTU_PB_257');

    var RAND_E_HEX = '7A32849E569C8888F25DE6F69A839D75057383F473ACF559ABD3C5D683294CEB',
        PUB_X_HEX = '00AFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A6589',
        PUB_Y_HEX = '01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C';

    describe("#add", function() {
        it("should produce specific point", function() {
            var rand_e = new Field(RAND_E_HEX, 'hex', curve),
                pub_x = new Field(PUB_X_HEX, 'hex', curve),
                pub_y = new Field(PUB_Y_HEX, 'hex', curve),
                pp_x = new Field('176dbde19773dfd335665597e8d6a0ab678721a5bb7030f25dc4c48b809ef3520', 'hex', curve),
                pp_y = new Field('6e75301556ea5d571403086691030f024c026907c8e818b2eedd9184d12040ee', 'hex', curve),
                pub_q, pub_2q;

                pub_q = curve.point(pub_x, pub_y);
                pub_2q = pub_q.add(pub_q)

                assert.equal(pub_2q.x.equals(pp_x), true);
                assert.equal(pub_2q.y.equals(pp_y), true)
        })
    })

    describe("#mul", function() {
        it("should produce specific point", function() {
            var rand_e = new Field(RAND_E_HEX, 'hex', curve),
                pub_x = new Field(PUB_X_HEX, 'hex', curve),
                pub_y = new Field(PUB_Y_HEX, 'hex', curve),
                pp_x = new Field('f26df77ca4c807c6b94f5c577415a1fce603a85ae7678717e16cb9a78de32d15', 'hex', curve),
                pp_y = new Field('1785fded2804bea15b02c4fd785fd3e98ab2435b8d78da44e195a9a088d3fc2d4', 'hex', curve),
                pub_q, point;

                pub_q = curve.point(pub_x, pub_y);
                point = pub_q.mul(rand_e);

                assert.equal(point.x.equals(pp_x), true);
                assert.equal(point.y.equals(pp_y), true);
        })
    })

    describe("#trace()", function() {
        it("should compute field trace", function() {
            var value_hex = '2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6';
            var value = new Field(value_hex, 'hex', curve);
            var trace = value.trace();

            assert.equal(trace, 1);
        })
    })

    describe("#expand()", function() {
        it("should compute coordinates from compressed point", function() {
            var coords = curve.expand(new Field([0], 'buf8', curve));
            assert.equal(coords.x.is_zero(), true);

            var coords = curve.expand("2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6");

            assert.equal(true, curve.base.equals(coords));

            var pt = curve.point("2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6");
            assert.equal(true, pt.equals(curve.base));
        })

        it("should check tax office pubkey decompression", function() {
            var compressed = new Field("01A77131A7C14F9AA6EA8C760D39673D5F0330FAB1118D55B55B7AF0735975485F", 'hex', curve);
            var pt = curve.point(compressed);
            var expect_pt = curve.point(
                new Field("01A77131A7C14F9AA6EA8C760D39673D5F0330FAB1118D55B55B7AF0735975485F", 'hex', curve),
                new Field("DC058ADA665D99084038B5F914FB9CF7214760A4865B49CAF7F4BE7379F3A395", 'hex', curve)
            );

            assert.equal(pt.equals(expect_pt), true);

            compressed = new Field("2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6", 'hex', curve);
            var pt = curve.point(compressed);
            var expect_pt = curve.point(
                new Field("2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7", 'hex', curve),
                new Field("010686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF", 'hex', curve) 
            );

            assert.equal(pt.equals(expect_pt), true);
        })
    })

    describe("#compress()", function() {
        it("should compress point coords", function() {
            var pt = curve.base;
            var compressed = pt.compress();

            var expected = new Field("2a29ef207d0e9b6c55cd260b306c7e007ac491ca1b10c62334a9e8dcd8d20fb6", 'hex', curve);

            assert.equal(compressed.equals(expected), true);
        })
    })
})

describe('Sign', function() {
    var curve = jk.std_curve('DSTU_PB_257'),
    priv_d = new Field('2A45EAFE4CD469F811737780C57253360FBCC58E134C9A1FDCD10B0E4529A143', 'hex', curve),
        hash_v = new Field('6845214B63288A832A772E1FE6CB6C7D3528569E29A8B3584370FDC65F474242', 'hex', curve),
        hash_b = new Buffer('6845214B63288A832A772E1FE6CB6C7D3528569E29A8B3584370FDC65F474242', 'hex'),
        rand_e = new Field('7A32849E569C8888F25DE6F69A839D75057383F473ACF559ABD3C5D683294CEB', 'hex', curve),
        sig_s = new Field('0CCC6816453A903A1B641DF999011177DF420D21A72236D798532AEF42E224AB', 'hex', curve),
        sig_r = new Field('491FA1EF75EAEF75E1F20CF3918993AB37E06005EA8E204BC009A1FA61BB0FB2', 'hex', curve),
        pub_x = new Field('00AFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A6589', 'hex', curve),
        pub_y = new Field('01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C', 'hex', curve);


    describe("#help_sign", function() {
        it("should sign long binary value with privkey and provided E", function() {
            var priv = new Priv(curve, priv_d), sig;
            sig = priv.help_sign(hash_v, rand_e);

            assert.equal(sig.s.toString(true), 'ccc6816453a903a1b641df999011177df420d21a72236d798532aef42e224ab')
            assert.equal(sig.r.toString(true), '491fa1ef75eaef75e1f20cf3918993ab37e06005ea8e204bc009a1fa61bb0fb2');
        })
    })

    describe("#sign", function() {
        it("should sign long binary value with privkey and generated E", function() {
            var priv = new Priv(curve, priv_d), sig;
            sig = priv.sign(hash_b);

            assert.equal(Object.keys(sig).length, 3);
        })

        it("should return buffer with asn1 string", function() {
            var priv = new Priv(curve, priv_d), sig;
            sig = priv.sign(hash_b, 'short');

            assert.equal(sig.length, 66);
            assert.equal(sig[0], 4);
            assert.equal(sig[1], 64);
        });
    })

    describe('#verify', function () {
        var sign_hex = '044091d08086a623d7fc292418636f634e82e52f8f989d423dae6c64878699cc2f11d0332bfe45c237421a41c2eb99e230f2629881c8e0c90be88610880e8c269d23';
        it("should parse asn1 signature", function() {
            var priv = new Priv(curve, priv_d),
                pub = priv.pub();

            ok = pub.verify(hash_b, new Buffer(sign_hex, 'hex'), 'short');
            assert.equal(ok, true);
        });
    });

    describe("#pub", function() {
        it("should return pubkey from priv", function() {
            var priv = new Priv(curve, priv_d),
                pub = priv.pub(),
                sig, ok;

            assert.equal(pub.x.equals(pub_x), true);
            assert.equal(pub.y.equals(pub_y), true);

            sig = priv.help_sign(hash_v, rand_e);
            ok = pub.help_verify(hash_v, sig.s, sig.r);
            assert.equal(ok, true);
        })
    })

    describe('sign_serialise()', function() {
        it("Should return asn1 string", function () {
            var asign, sign;

            var hex = '0440b20fbb61faa109c04b208eea0560e037ab938991f30cf2e175efea75efa11f49ab24e242ef2a5398d73622a7210d42df77110199f91d641b3a903a451668cc0c';

            sign = {
                s: new Field('ccc6816453a903a1b641df999011177df420d21a72236d798532aef42e224ab', 'hex', curve),
                r: new Field('491fa1ef75eaef75e1f20cf3918993ab37e06005ea8e204bc009a1fa61bb0fb2', 'hex', curve)
            };
            asign = Priv.sign_serialise(sign, 'short');

            assert.equal(asign.toString('hex'), hex);

        });
    });

    describe('parse_sign()', function() {
        it("Should parse asn1 string to {s, r} object", function() {
            var asign, sign;

            var hex = '0440b20fbb61faa109c04b208eea0560e037ab938991f30cf2e175efea75efa11f49ab24e242ef2a5398d73622a7210d42df77110199f91d641b3a903a451668cc0c';

            sign = {
                s: 'ccc6816453a903a1b641df999011177df420d21a72236d798532aef42e224ab',
                r: '491fa1ef75eaef75e1f20cf3918993ab37e06005ea8e204bc009a1fa61bb0fb2'
            };
            asign = Pub.parse_sign(new Buffer(hex, 'hex'), 'short', curve);

            assert.equal(asign.s.toString(true), sign.s);
            assert.equal(asign.r.toString(true), sign.r);

        });
    });

})

describe('Broken', function() {
    var curve = jk.std_curve('DSTU_PB_257');

    describe("#expand()", function() {
        it("should compute coordinates from specific point", function() {
            var compressed = new Field("76cd4555ad63455529755e5c3f3066c3bcb957cc63d00e22c6dd1e9ed316b419", 'hex', curve);

            var coords = curve.expand(compressed);

            var px = new Field('76cd4555ad63455529755e5c3f3066c3bcb957cc63d00e22c6dd1e9ed316b418', 'hex', curve);
            var py = new Field('12b20103548f45dcbed5486022dfcb244b2d996e0d3d761abaf73ba16ea26e0d3', 'hex', curve);
            var expect_pt = curve.point(px, py);

            assert.equal(true, expect_pt.equals(coords));
        })
    })

})
