/* eslint-env mocha */
/* eslint-disable no-plusplus */
const assert = require("assert");

const gf2m = require("../lib/gf2m.js");

describe("Field", () => {
  describe("#mod", () => {
    it("should return mod of value", () => {
      const valueA = new Uint32Array([
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
      const valueP = new Uint32Array([0x00000101, 0x0000000c]);
      const expect = new Uint32Array([
        0x29a60895,
        0x87025056,
        0x90f62ba8,
        0x94aa6314,
        0xde5742e1,
        0x85849e20,
        0xb4292849,
        0xff3ee09c,
        0
      ]);

      let ret;
      let idx;
      for (idx = 0; idx < 10000; idx++) ret = gf2m.mod(valueA, valueP);

      assert.equal(ret.length, expect.length);
      for (idx = 0; idx < ret.length; idx++) {
        assert.equal(ret[idx], expect[idx]);
      }
    });
  });
});
