import { describe, it, expect } from "vitest";
import { invert, BIG_INVERT } from "../lib/util.js";

// Regression for the ESM strict-mode crash: invert() used `i` without
// declaring it, which silently created a global in the old CJS build and
// threw ReferenceError from dist/index.mjs.
describe("bit inversion", () => {
  it("inverts a byte string", () => {
    expect(Array.from(invert(Buffer.from([0x01, 0x02, 0x03])))).toEqual([
      192,
      64,
      128
    ]);
  });

  it("BIG_INVERT prepends a zero byte", () => {
    expect(Array.from(BIG_INVERT(Buffer.from([0x01, 0x02, 0x03])))).toEqual([
      0,
      192,
      64,
      128
    ]);
  });
});
