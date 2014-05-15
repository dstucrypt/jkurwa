var assert = require("assert"),
    Big = require('../big.js');
    val_hex = 'aff3ee09cb429284985849e20de5742e194aa631490f62ba88702505629a65890',
    rv_hex = 'ff3ee09cb429284985849e20de5742e194aa631490f62ba88702505629a60895',
    Curve = require('../curve.js'),
    Field = Curve.Field;


describe('Curve', function() {
    describe('#comp_modulus()', function() {
        it('should compute curve modulus', function() {
            var curve = new Curve(),
                mod_hex = "20000000000000000000000000000000000000000000000000000000000001001",
                mod = new Big(mod_hex, 16);

            curve.comp_modulus(257, 12, 0);
            assert.equal(0, mod.compareTo(curve.modulus));
            assert.equal(258, curve.modulus.bitLength());
        })
    })
})

describe("Field", function() {
    var curve = new Curve;
    curve.comp_modulus(257, 12, 0);

    describe("#mod", function() {
        it("should return mod of value", function() {
            var field_a, value_a, expect_b;

            value_a = new Big(val_hex, 16);
            expect_b = new Big(rv_hex, 16);
            field_a = curve.field(value_a);
            assert.equal(0, field_a.value.compareTo(expect_b));
        })
    })
    
    describe("#mul", function() {
        it("should return product of two values", function() {
            var value_a, field_a, value_b, hex_b, value_c, expect_hex, expect_c;

            hex_b = '01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C';
            expect_hex = '157b8e91c8b225469821fc836045a7c09c30d9fdee54b680c8247821f8c4e3352';
            value_a = new Big(val_hex, 16);
            value_b = new Big(hex_b, 16);
            expect_c = new Big(expect_hex, 16);

            field_a = curve.field(value_a);
            value_c = field_a.mul(value_b);

            assert.equal(0, value_c.compareTo(expect_c));

        })
    })

    describe('#inv', function() {
        it("should return negative of r", function() {
            expect_r_hex = 'f5ae84d0c4dc2e7e89c670fb2083d124be50b413efb6863705bd63a5168352e0';
            value_a = new Big(val_hex, 16);
            field_a = curve.field(value_a);

            value_r = field_a.inv();
        })
    })
})
