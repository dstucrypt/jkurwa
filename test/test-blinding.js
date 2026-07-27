import { expect, test } from "vitest";
import Point from "../lib/point.js";
import { std_curve } from "../lib/curve.js";

// Regression guard for the timing-side-channel countermeasure in
// lib/models/Priv.js (fixed_length_scalar): the scalar handed to point
// multiplication during signing must have a bit length that does not
// depend on the secret nonce.
test("signing scalar has constant bit length and signatures verify", () => {
  const curve = std_curve("DSTU_PB_257");
  const priv = curve.keygen();
  const pub = priv.pub();

  const seen = [];
  const origMul = Point.prototype.mul;
  Point.prototype.mul = function (n) {
    seen.push(n.bitLength());
    return origMul.call(this, n);
  };

  try {
    const hash = Buffer.alloc(32, 7);
    const lengthsSeen = new Set();
    for (let i = 0; i < 3; i++) {
      seen.length = 0;
      const sig = priv.sign(hash, "short");
      expect(pub.verify(hash, sig, "short")).toBe(true);
      lengthsSeen.add(seen[0]);
    }

    const orderBits = curve.order.bitLength();
    // Padding with the group order pins the scalar to orderBits + 1 bits
    // on every signing, regardless of the nonce value: no length leak.
    expect(lengthsSeen.size).toBe(1);
    expect([...lengthsSeen][0]).toBe(orderBits + 1);
  } finally {
    Point.prototype.mul = origMul;
  }
});
