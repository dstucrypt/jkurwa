var assert = require("assert"),
    gf2m = require('../lib/gf2m.js');

var val_hex = 'aff3ee09cb429284985849e20de5742e194aa631490f62ba88702505629a65890',
    rv_hex = 'ff3ee09cb429284985849e20de5742e194aa631490f62ba88702505629a60895';


describe("Field", function() {
    describe("#mod", function() {
        it("should return mod of value", function() {
            var value_a = new Uint32Array([
                0x29a65890,
                0x87025056,
                0x90f62ba8,
                0x94aa6314,
                0xde5742e1,
                0x85849e20,
                0xb4292849,
                0xff3ee09c,
                0xa
            ]);
            var value_p = new Uint32Array([
                0x00000101, 0x0000000c
            ]);
            var expect = new Uint32Array([
                0x29a60895, 0x87025056, 0x90f62ba8,
                0x94aa6314, 0xde5742e1, 0x85849e20,
                0xb4292849, 0xff3ee09c, 0
            ]);

            var ret, idx;
            for (idx=0; idx < 10000; idx++)
                ret = gf2m.mod(value_a, value_p);

            assert.equal(ret.length, expect.length);
            for (idx = 0; idx < ret.length; idx++) {
                assert.equal(ret[idx], expect[idx]);
            }
        })
    })

    describe('inv()', function () {
        it('should invert field value', function () {
        });
    });
});
