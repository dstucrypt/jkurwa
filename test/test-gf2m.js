var gf2m = require('../lib/gf2m.js'),
    jk = require('../curve.js'),
    assert = require("assert");


describe("Field", function () {
    var curve = jk.defined.DSTU_B_257;

    describe("Field()", function() {
        it("should create bitfield from hex str", function () {
            var a = curve.field("1d5c1390f11e3e87fc7e163d1492b0ac169e7b0cb44e95a4da32183a9e2189039", 'hex');
            a_buf = new Uint32Array([
                0xa9e2189039, 0xa32183a9, 0x44e95a4d, 0x69e7b0cb,
                0x492b0ac1,   0xc7e163d1, 0x11e3e87f, 0xd5c1390f,
                0x1
            ]);

            assert.equal(a.bytes.length, 9); // word count for this curve

            for(var i=0; i < a.bytes.length; i++) {
                assert.equal(a_buf[i], a.bytes[i]);
            }
        });

    });

    describe("#add()", function() {
        it("should add one bitfield to another", function() {
            var a = curve.field("1313FFA0FFFF7777", 'hex');
            var b = curve.field("212F888411116666", 'hex');

            var res = a.add(b);

            assert.equal(true, res.toString() === '<Field 323c7724eeee1111>');
            assert.equal(true, a.toString() === '<Field 1313ffa0ffff7777>');
            assert.equal(true, b.toString() === '<Field 212f888411116666>');
        });
    });

    describe("#addM()", function() {
        it("should add one bitfield to another inplace", function() {
            var a = curve.field("1313FFA0FFFF7777", 'hex');
            var b = curve.field("212F888411116666", 'hex');

            a.addM(b);

            assert.equal(true, a.toString() === '<Field 323c7724eeee1111>');
            assert.equal(true, b.toString() === '<Field 212f888411116666>');
        });
    });

    describe('#invert()', function() {
        it('should invert bitfield', function () {
            var a = curve.field("1d5c1390f11e3e87fc7e163d1492b0ac169e7b0cb44e95a4da32183a9e2189039", 'hex');

            a_inv = a.invert();
            assert.equal(true, '<Field 1541090d2f4b532a3cdbfe3ca9db032e336b48b256d2022a050fa5dd3cb1fc574>' == a_inv.toString());
        });
    });
});

describe('GF(2m)', function() {

    var curve = jk.defined.DSTU_B_257;

    describe('mul_2x2', function() {
        it("should compute product of of two polynomials", function() {
            var x1, x0, y1, y0, x, y, ret, big;

            x1 = 0xA32183A9;
            x0 = 0xE2189039;
            y1 = 0x2C5DD8BA;
            y0 = 0x589BB063;

            ret = new Uint32Array(6);

            gf2m.mul_2x2(x1, x0, y1, y0, ret);
            assert.equal(0x694892b, ret[0]);
            assert.equal(0xb5b71bfa, ret[1]);
            assert.equal(0x9f7fd5a0, ret[2]);
            assert.equal(0x13d4008d, ret[3]);

        })
    });

    describe('mod_mul()', function() {
        it("should compube product of two big polynomals", function() {

            var a = curve.field("1d5c1390f11e3e87fc7e163d1492b0ac169e7b0cb44e95a4da32183a9e2189039", "hex")
                b = curve.field("144f9fc971f0e0abeb75dc13dcb8287e52c78ecdbb5ebebbb2c5dd8ba589bb063", "hex"),
                expect_ret_str = '1494b88ac670ea6e57e2c1e7f2229774cc3218fd46d2fe6e552822d8645d95f2a';

            ret = a.mod_mul(b);

            assert.equal('<Field ' + expect_ret_str + '>', ret.toString());

        });
    });

    describe('shiftLeft()', function() {
        it("generic shift bytearray contents left", function() {
            var a = new Uint32Array([
                0xe2189039, 0xA329A14A
            ]);
            var b = new Uint32Array(3);
            gf2m.lShiftXor(a, 4, b);
            assert.equal(b[0], 0x21890390);
            assert.equal(b[1], 0x329A14AE);

            b = new Uint32Array(4);
            gf2m.lShiftXor(a, 36, b);
            assert.equal(b[3], 0xA);
            assert.equal(b[2], 0x329A14AE);
            assert.equal(b[1], 0x21890390);
            assert.equal(b[0], 0);

            var b = new Uint32Array(3);
            gf2m.l1ShiftXor(a, b);
            assert.equal(b[0], 0xc4312072)

        })

        it("should shift bytearray contents left by one", function() {
            var a = new Uint32Array([
                0xe69f323, 0x3595e71e
            ]);
            var b = new Uint32Array(a.length + 1);
            gf2m.l1ShiftXor(a, b);

            assert.equal(0x1cd3e646, b[0]);
            assert.equal(0x6b2bce3c, b[1]);
            assert.equal(0, b[2]);
        })
    })


    describe('shiftRight()', function() {
        it("should shift bytearray contents right", function() {
            var a = new Uint32Array([
                0xe2189039, 0xA329A14A
            ]);
            var b = gf2m.shiftRight(a, 4);

            assert.equal(b[0], 0xAe218903);
            assert.equal(b[1], 0x0A329A14);

            var a = new Uint32Array([
                0xe2189039, 0xA329A14A
            ]);
            b = gf2m.shiftRight(a, 31);

            assert.equal(b[0], 0x46534295);
            assert.equal(b[1], 1);

            var a = new Uint32Array([
                0xe2189039, 0xA329A14A
            ]);
            b = gf2m.shiftRight(a, 36);

            assert.equal(a[0], 0xe2189039);
            assert.equal(a[1], 0xA329A14A);
            assert.equal(b[0], 0x0A329A14);
            assert.equal(b[1], 0);

            b = gf2m.shiftRight(a, 36, true);
            assert.equal(b, a);

        });
    })
});
