import { describe, it } from "vitest";
import assert from "node:assert";

import * as jk from "../lib/index.js";

/* Priv.from_protected() (no password) runs each candidate buffer through
 * guessStore(), which tries Priv.from_asn1() first and, on any failure,
 * silently falls through to the cert-bag parser. When the input is neither
 * a valid private key store nor a valid cert bag, callers used to see only
 * the cert-bag parser's unrelated failure ("Failed to match tag: seq" and
 * similar) with the original, often more useful, from_asn1 error discarded
 * -- which is exactly what hid the `jk is not defined` ReferenceError
 * behind a confusing asn1 tag-mismatch error before it was diagnosed. */
describe("guessStore diagnostics", () => {
  it("surfaces the original from_asn1 failure when no candidate parses", () => {
    const garbage = Buffer.from([0x30, 0x03, 0x01, 0x02, 0x03]);

    assert.throws(
      () => jk.Priv.from_protected(garbage),
      /version/,
      "expected the private-key parse error to be part of the thrown message"
    );
  });
});
