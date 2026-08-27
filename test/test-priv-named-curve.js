import { describe, it } from "vitest";
import assert from "node:assert";

import * as jk from "../lib/index.js";

/* Minimal DER encoding helpers to build a PKCS#8 DSTU key
 * that references the curve by OID (named curve) instead of
 * spelling out explicit curve parameters. Keys issued by bank
 * CAs (e.g. monobank / Universal Bank .pfx containers) use
 * this form, while the fixture keys in test/data carry
 * explicit parameters — which is why the broken branch in
 * Priv.from_asn1 (`jk.std_curve` with no `jk` in scope,
 * ReferenceError "jk is not defined") went unnoticed. */
const lenBytes = len => {
  if (len < 0x80) return Buffer.from([len]);
  const b = [];
  let v = len;
  while (v > 0) {
    b.unshift(v & 0xff);
    v >>= 8;
  }
  return Buffer.from([0x80 | b.length, ...b]);
};
const tlv = (tag, content) =>
  Buffer.concat([Buffer.from([tag]), lenBytes(content.length), content]);
const seq = (...parts) => tlv(0x30, Buffer.concat(parts));
const octstr = b => tlv(0x04, b);
const int0 = tlv(0x02, Buffer.from([0]));
const oid = dotted => {
  const p = dotted.split(".").map(Number);
  const bytes = [p[0] * 40 + p[1]];
  for (const arc of p.slice(2)) {
    const chunk = [];
    let v = arc;
    do {
      chunk.unshift(v & 0x7f);
      v >>= 7;
    } while (v > 0);
    for (let i = 0; i < chunk.length - 1; i++) chunk[i] |= 0x80;
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
};

const OID_DSTU4145_LE = "1.2.804.2.1.1.1.1.3.1.1";
const OID_CURVE_PB257 = "1.2.804.2.1.1.1.1.3.1.1.2.6";

function namedCurveKey() {
  // PKCS#8-style DstuPrivkey:
  // SEQ { INTEGER 0,
  //       SEQ { OID dstu4145le, SEQ { Curve ::= OID (named) } },
  //       OCTET STRING param_d (LE) }
  const d = Buffer.alloc(32, 0x42);
  d[31] = 0x01; // keep d well below the group order
  return seq(int0, seq(oid(OID_DSTU4145_LE), seq(oid(OID_CURVE_PB257))), octstr(d));
}

describe("Priv.from_asn1 with named curve", () => {
  it("parses a key that references the curve by OID", () => {
    const priv = jk.Priv.from_asn1(namedCurveKey());
    assert.equal(priv.type, "Priv");
    assert.ok(priv.curve.equals(jk.std_curve("DSTU_PB_257")));
  });

  it("returns a store when asked to", () => {
    const store = jk.Priv.from_asn1(namedCurveKey(), true);
    assert.equal(store.format, "privkeys");
    assert.equal(store.keys.length, 1);
    assert.equal(store.keys[0].type, "Priv");
  });
});
