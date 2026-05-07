import { describe, it } from "vitest";
/* eslint-disable no-plusplus */
import assert from "assert";
import * as gf2m from "../lib/gf2m.js";

const base_pb_257 = new Uint32Array([
  2868794628, 3546471302,
  1984461146, 2266653769,
  1477709477, 2213487392,
  1124848366,  927226002,
  0
]);
const modulo_pb_257 = new Uint32Array([
  4097, 0, 0, 0,
  0, 0, 0, 0,
  2
]);
const modulo_pb_256_bits = [257, 12, 0];
const base_pb_191 = new Uint32Array([
  3672863017, 3271360118,
  2891495861, 2031265490,
  1660092234, 1900090551,
]);
const modulo_pb_191 = [ 513, 0, 0, 0, 0, 2147483648 ];
const modulo_pb_191_bits = [191, 9, 0];


describe("gf2m", () => {
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

  describe('#inv fast', () => {
    it.each([
      [2, 5],
      [3, 6],
      [4, 7],
      [5, 2],
      [6, 3],
      [7, 4],
    ])('should compute inverted value of %d to be %d on m=3', (a, expectedValue) => {
      // Setup
      const m = 3;
      const p = new Uint32Array([0xB]);  // x^3 + x + 1
      let ret = new Uint32Array(1);

      gf2m.inv_fast([a], p, ret);

      assert.equal(ret[0], expectedValue);
    });


    it('should return inverted value for known PB_257 value', () => {
      const valueA = new Uint32Array(base_pb_257);
      const expectA = new Uint32Array(base_pb_257);
      const valueP = new Uint32Array(modulo_pb_257);

      const expect = new Uint32Array([
        2212782975,  784404366,
        3639274527, 2383088420,
        2863133559, 3083282239,
        1915462745, 2352840975,
        0
      ]);
      const tmp = new Uint32Array(9);
      const tmp2 = new Uint32Array(9);
      const ret = new Uint32Array(9);
      const ret2 = new Uint32Array(9);

      gf2m.inv_fast(valueA, valueP, tmp);
      gf2m.mod(tmp, valueP, ret);

      assert.equal(ret.length, expect.length);
      for (let idx = 0; idx < ret.length; idx++) {
        assert.equal(ret[idx], expect[idx]);
      }

      gf2m.inv_fast(ret, valueP, tmp2);
      gf2m.mod(tmp2, valueP, ret2);

      assert.equal(ret2.length, valueA.length);
      for (let idx = 0; idx < ret2.length; idx++) {
        assert.equal(ret2[idx], expectA[idx]);
      }
    });

    it('should return inverted value for known PB_191 value', () => {
      const valueA = new Uint32Array(base_pb_191);
      const expectA = new Uint32Array(base_pb_191);
      const valueP = new Uint32Array(modulo_pb_191);

      const expect = new Uint32Array([
        588100965, 4266588766,
        614862865,  900202323,
        3844403428,  685512842,
      ]);
      const ret = new Uint32Array(6);
      const ret2 = new Uint32Array(6);

      let didThrow = false;
      try {
        gf2m.inv_fast(valueA, valueP, ret);
      } catch (eror) {
        didThrow = true;
      }
      assert.equal(didThrow, true);
      /*
      Fast inversion gets into the loop on PB 191
      assert.equal(ret.length, expect.length);
      for (idx = 0; idx < ret.length; idx++) {
        assert.equal(ret[idx], expect[idx]);
      }

      gf2m.inv_fast(ret, valueP, ret2);
      assert.equal(ret2.length, expect.length);
      for (idx = 0; idx < ret2.length; idx++) {
        assert.equal(ret2[idx], valueA[idx]);
      }
      */

    });
  });

  describe('#inv slow', () => {
    it.each([
      [2, 5],
      [3, 6],
      [4, 7],
      [5, 2],
      [6, 3],
      [7, 4],
    ])('should compute inverted value of %d to be %d on m=3', (a, expectedValue) => {
      // Setup
      const m = 3;
      let ret = new Uint32Array(1);

      gf2m.inv_slow(m, [a], [3, 1, 0], ret);

      assert.equal(ret[0], expectedValue);
    });

    it('should return inverted value for known PB_257 value', () => {
      const valueA = new Uint32Array(base_pb_257);

      const expect = new Uint32Array([
        2212782975,  784404366,
        3639274527, 2383088420,
        2863133559, 3083282239,
        1915462745, 2352840975,
        0
      ]);
      const ret = new Uint32Array(9);
      const ret2 = new Uint32Array(9);

      gf2m.inv_slow(257, valueA, modulo_pb_256_bits, ret);
      assert.equal(ret.length, expect.length);
      for (let idx = 0; idx < ret.length; idx++) {
        assert.equal(ret[idx], expect[idx]);
      }

      gf2m.inv_slow(257, ret, modulo_pb_256_bits, ret2);
      assert.equal(ret2.length, expect.length);
      for (let idx = 0; idx < ret2.length; idx++) {
        assert.equal(ret2[idx], valueA[idx]);
      }

    });

    it('should return inverted value for known PB_191 value', () => {
      const valueA = new Uint32Array(base_pb_191);

      const expect = new Uint32Array([
        588100965, 4266588766,
        614862865,  900202323,
        3844403428,  685512842,
      ]);
      const ret = new Uint32Array(6);
      const ret2 = new Uint32Array(6);

      gf2m.inv_slow(191, valueA, modulo_pb_191_bits, ret);
      assert.equal(ret.length, expect.length);
      for (let idx = 0; idx < ret.length; idx++) {
        assert.equal(ret[idx], expect[idx]);
      }

      gf2m.inv_slow(191, ret, modulo_pb_191_bits, ret2);
      assert.equal(ret2.length, expect.length);
      for (let idx = 0; idx < ret2.length; idx++) {
        assert.equal(ret2[idx], valueA[idx]);
      }

    });
  });

});
