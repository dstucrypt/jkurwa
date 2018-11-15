/* eslint-env mocha */
const assert = require("assert");

const jk = require("../lib/index.js");

describe("B64", () => {
  describe("b64_encode()", () => {
    it("should encode 0 as AA", () => {
      assert.equal("AA", jk.b64_encode([0]));
    });
    it("should encode 1 as AA", () => {
      assert.equal("AQ", jk.b64_encode([1]));
    });
    it("should pad sinhgle-byte zero with two pad symbols", () => {
      assert.equal("AA==", jk.b64_encode([0], { pad: true }));
    });
    it("should pad two-byte zero with one pad symbol", () => {
      assert.equal("AAA=", jk.b64_encode([0, 0], { pad: true }));
    });
    it("should not pad three bytes", () => {
      assert.equal("AAAA", jk.b64_encode([0, 0, 0], { pad: true }));
    });
  });
});
