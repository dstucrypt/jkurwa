import { describe, it } from "vitest";
import assert from "assert";

import { b64_encode } from "../lib/util/base64";

describe("B64", () => {
  describe("b64_encode()", () => {
    it("should encode 0 as AA", () => {
      assert.equal("AA", b64_encode([0]));
    });
    it("should encode 1 as AA", () => {
      assert.equal("AQ", b64_encode([1]));
    });
    it("should pad sinhgle-byte zero with two pad symbols", () => {
      assert.equal("AA==", b64_encode([0], { pad: true }));
    });
    it("should pad two-byte zero with one pad symbol", () => {
      assert.equal("AAA=", b64_encode([0, 0], { pad: true }));
    });
    it("should not pad three bytes", () => {
      assert.equal("AAAA", b64_encode([0, 0, 0], { pad: true }));
    });
  });
});
