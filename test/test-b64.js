var assert = require("assert"),
    jk = require('../lib/index.js');

describe('B64', function() {
    describe('b64_encode()', function() {
        it("should encode 0 as AA", function() {
            assert.equal("AA", jk.b64_encode([0]));
        });
        it("should encode 1 as AA", function() {
            assert.equal("AQ", jk.b64_encode([1]));
        });
        it("should pad sinhgle-byte zero with two pad symbols", function () {
            assert.equal("AA==", jk.b64_encode([0], {pad: true}));
        })
        it("should pad two-byte zero with one pad symbol", function () {
            assert.equal("AAA=", jk.b64_encode([0, 0], {pad: true}));
        })
        it("should not pad three bytes", function () {
            assert.equal("AAAA", jk.b64_encode([0, 0, 0], {pad: true}));
        })

    });
});

