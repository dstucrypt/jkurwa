import { describe, it } from "vitest";
import gost89 from "gost89";
import assert from "assert";
import { loadPriv, loadCert } from "./utils.js";

import * as kupyna from "../lib/util/kupyna.js";
import * as rfc3280 from "../lib/spec/rfc3280.js";
import Message from "../lib/models/Message.js";
import Box from "../lib/app/ctx.js";

describe("Kupyna (DSTU 7564:2014)", () => {
  const hash = kupyna.algos().hash;

  describe("hash adapter", () => {
    it("exposes a Buffer-returning hash tagged with the DSTU 7564 OID name", () => {
      const out = hash(Buffer.from("hello world"));
      assert.ok(Buffer.isBuffer(out));
      assert.equal(out.length, 32);
      assert.equal(hash.algo, "Dstu7564-256");
    });

    it("matches the official Kupyna-256 empty-string vector", () => {
      assert.equal(
        hash(Buffer.alloc(0)).toString("hex"),
        "cd5101d1ccdf0d1d1f4ada56e888cd724ca1a0838a3521e7131d4fb78d0f5eb6"
      );
    });

    it("matches the official Kupyna-256 vector for the 512-bit message", () => {
      const message = Buffer.from(Array.from({ length: 64 }, (_, i) => i));
      assert.equal(
        hash(message).toString("hex"),
        "08f4ee6f1be6903b324c4e27990cb24ef69dd58dbe84813ee0a52f6631239875"
      );
    });

    it("supports 384 and 512 variants with correct tags and sizes", () => {
      assert.equal(kupyna.hash384(Buffer.alloc(0)).length, 48);
      assert.equal(kupyna.hash384.algo, "Dstu7564-384");
      assert.equal(kupyna.hash512(Buffer.alloc(0)).length, 64);
      assert.equal(kupyna.hash512.algo, "Dstu7564-512");
    });

    // Official DSTU 7564:2014 vectors for the sequential-byte messages
    // (00 01 02 ...), as published in the Kupyna paper (IACR ePrint
    // 2015/885, appendix) and used by Bouncy Castle's DSTU7564Test.
    const seq = bytes =>
      Buffer.from(Array.from({ length: bytes }, (_, i) => i & 0xff));

    it("matches the official Kupyna-384 vector for the 760-bit message", () => {
      assert.equal(
        kupyna.hash384(seq(95)).toString("hex"),
        "d9021692d84e5175735654846ba751e6d0ed0fac36dfbc0841287dcb0b5584c7" +
          "5016c3decc2a6e47c50b2f3811e351b8"
      );
    });

    it("matches the official Kupyna-512 empty-string vector", () => {
      assert.equal(
        kupyna.hash512(Buffer.alloc(0)).toString("hex"),
        "656b2f4cd71462388b64a37043ea55dbe445d452aecd46c3298343314ef04019" +
          "bcfa3f04265a9857f91be91fce197096187ceda78c9c1c021c294a0689198538"
      );
    });

    it("matches the official Kupyna-512 vector for the 512-bit message", () => {
      assert.equal(
        kupyna.hash512(seq(64)).toString("hex"),
        "3813e2109118cdfb5a6d5e72f7208dccc80a2dfb3afdfb02f46992b5edbe536b" +
          "3560dd1d7e29c6f53978af58b444e37ba685c0dd910533ba5d78efffc13de62a"
      );
    });

    it("matches the official Kupyna-512 vector for the 1024-bit message", () => {
      assert.equal(
        kupyna.hash512(seq(128)).toString("hex"),
        "76ed1ac28b1d0143013ffa87213b4090b356441263c13e03fa060a8cada32b97" +
          "9635657f256b15d5fca4a174de029f0b1b4387c878fcc1c00e8705d783fd7ffe"
      );
    });

    it("matches the official Kupyna-512 vector for the 2048-bit message", () => {
      assert.equal(
        kupyna.hash512(seq(256)).toString("hex"),
        "0dd03d7350c409cb3c29c25893a0724f6b133fa8b9eb90a64d1a8fa93b565566" +
          "11eb187d715a956b107e3bfc76482298133a9ce8cbc0bd5e1436a5b197284f7e"
      );
    });

    it("matches the official Kupyna-512 vector for the single byte 0xFF", () => {
      assert.equal(
        kupyna.hash512(Buffer.from([0xff])).toString("hex"),
        "871b18cf754b72740307a97b449abeb32b64444cc0d5a4d65830ae5456837a72" +
          "d8458f12c8f06c98c616abe11897f86263b5cb77c420fb375374bec52b6d0292"
      );
    });
  });

  describe("OID registration", () => {
    it("round-trips the Kupyna hash OID through the ASN.1 layer", () => {
      const der = rfc3280.AlgorithmIdentifier.encode(
        { algorithm: "Dstu7564-256" },
        "der"
      );
      // 1.2.804.2.1.1.1.1.2.2.1
      assert.ok(der.includes(Buffer.from("2a86240201010101020201", "hex")));
      const back = rfc3280.AlgorithmIdentifier.decode(der, "der");
      assert.equal(back.algorithm, "Dstu7564-256");
    });

    it("maps the DSTU4145-with-Kupyna signature OID", () => {
      const der = rfc3280.AlgorithmIdentifier.encode(
        { algorithm: "Dstu4145le-Dstu7564-256" },
        "der"
      );
      assert.equal(
        rfc3280.AlgorithmIdentifier.decode(der, "der").algorithm,
        "Dstu4145le-Dstu7564-256"
      );
    });
  });

  describe("signed message", () => {
    const key1 = loadPriv("PRIV1.cer");
    const cert = loadCert("SELF_SIGNED1.cer");
    const gostAlgo = gost89.compat.algos();
    const data = Buffer.from("123");
    const time = 1540236305;

    function signWith(hashFn) {
      return new Message({
        type: "signedData",
        cert,
        data,
        hash: hashFn,
        signTime: time,
        signer: key1
      });
    }

    it("stamps Kupyna OID into digestAlgorithms and signerInfo", () => {
      const message = signWith(hash);
      const { content } = message.wrap;
      assert.equal(content.digestAlgorithms[0].algorithm, "Dstu7564-256");
      assert.equal(
        content.signerInfos[0].digestAlgorithm.algorithm,
        "Dstu7564-256"
      );
    });

    it("preserves the Kupyna OID across ASN.1 serialization round-trip", () => {
      const parsed = new Message(signWith(hash).as_asn1());
      assert.equal(parsed.digestAlgo, "Dstu7564-256");
      assert.equal(
        parsed.wrap.content.digestAlgorithms[0].algorithm,
        "Dstu7564-256"
      );
    });

    it("verifies attributes with Kupyna hash but not with GOST hash", () => {
      const parsed = new Message(signWith(hash).as_asn1());
      assert.equal(parsed.verifyAttrs(hash), true);
      assert.equal(parsed.verifyAttrs(gostAlgo.hash), false);
    });

    it("keeps GOST 34.311 as the default when the hash is untagged", () => {
      const message = signWith(gostAlgo.hash);
      assert.equal(
        message.wrap.content.digestAlgorithms[0].algorithm,
        "Gost34311"
      );
    });
  });

  describe("automatic hash selection by certificate", () => {
    const gostAlgo = gost89.compat.algos();
    // Plain GOST algo — no Kupyna configuration whatsoever. Kupyna is seeded
    // by the Box automatically.
    const box = new Box({ algo: gostAlgo });

    it("picks GOST 34.311 for a legacy Dstu4145le certificate", () => {
      const picked = box.hashForCert({ signatureAlgorithm: "Dstu4145le" });
      assert.equal(picked, gostAlgo.hash);
      assert.equal(picked.algo, undefined); // untagged -> Gost34311
    });

    it("picks Kupyna-256 for a Dstu4145le-Dstu7564-256 certificate", () => {
      const picked = box.hashForCert({
        signatureAlgorithm: "Dstu4145le-Dstu7564-256"
      });
      assert.equal(picked.algo, "Dstu7564-256");
    });

    it("picks Kupyna-256 for the PB (polynomial basis) variant OID", () => {
      const picked = box.hashForCert({
        signatureAlgorithm: "Dstu4145le-Dstu7564-256-pb"
      });
      assert.equal(picked.algo, "Dstu7564-256");
    });

    it("picks the matching Kupyna size for 384/512 certificates", () => {
      assert.equal(
        box.hashForCert({ signatureAlgorithm: "Dstu4145le-Dstu7564-512" }).algo,
        "Dstu7564-512"
      );
      assert.equal(
        box.hashForCert({ signatureAlgorithm: "Dstu4145le-Dstu7564-384" }).algo,
        "Dstu7564-384"
      );
    });

    it("verifies a Kupyna-signed message with a plain GOST Box (zero config)", () => {
      assert.equal(box.hashMaps.byDigest["Dstu7564-256"].algo, "Dstu7564-256");
      assert.equal(
        box.hashMaps.bySig["Dstu4145le-Dstu7564-256"].algo,
        "Dstu7564-256"
      );
      // keyid slot stays GOST even with Kupyna seeded
      assert.equal(box.hashMaps.bySig.Dstu4145le, gostAlgo.hash);
    });
  });

  describe("forced hash (hashMethod / opts.hash)", () => {
    const gostAlgo = gost89.compat.algos();
    const gostCert = { signatureAlgorithm: "Dstu4145le" };
    const kupynaCert = { signatureAlgorithm: "Dstu4145le-Dstu7564-256" };

    it("auto by default (unset) — follows the certificate", () => {
      const box = new Box({ algo: gostAlgo });
      assert.equal(box.resolveSignHash(gostCert).algo, undefined); // GOST
      assert.equal(box.resolveSignHash(kupynaCert).algo, "Dstu7564-256");
    });

    it("Box hashMethod:'kupyna' forces Kupyna even for a GOST cert", () => {
      const box = new Box({ algo: gostAlgo, hashMethod: "kupyna" });
      assert.equal(box.resolveSignHash(gostCert).algo, "Dstu7564-256");
    });

    it("Box hashMethod:'gost' forces GOST even for a Kupyna cert", () => {
      const box = new Box({ algo: gostAlgo, hashMethod: "gost" });
      assert.equal(box.resolveSignHash(kupynaCert), gostAlgo.hash);
      assert.equal(box.resolveSignHash(kupynaCert).algo, undefined);
    });

    it("per-call opts.hash overrides the Box default", () => {
      const box = new Box({ algo: gostAlgo, hashMethod: "kupyna" });
      // override kupyna -> gost for this one call
      assert.equal(box.resolveSignHash(kupynaCert, "gost"), gostAlgo.hash);
    });

    it("per-call 'auto' overrides a Box default back to per-cert selection", () => {
      const box = new Box({ algo: gostAlgo, hashMethod: "kupyna" });
      assert.equal(box.resolveSignHash(gostCert, "auto").algo, undefined);
      assert.equal(
        box.resolveSignHash(kupynaCert, "auto").algo,
        "Dstu7564-256"
      );
    });

    it("accepts size aliases and a raw hash function", () => {
      const box = new Box({ algo: gostAlgo });
      assert.equal(
        box.resolveSignHash(gostCert, "kupyna-512").algo,
        "Dstu7564-512"
      );
      assert.equal(
        box.resolveSignHash(gostCert, kupyna.hash384).algo,
        "Dstu7564-384"
      );
    });

    it("accepts a custom tagged hash function at Box and per-call level", () => {
      const myHash = buf => kupyna.hash256(buf);
      myHash.algo = "Dstu7564-256";
      // as Box default
      const box = new Box({ algo: gostAlgo, hashMethod: myHash });
      assert.equal(box.resolveSignHash(gostCert), myHash);
      // per-call, overriding a string default
      const box2 = new Box({ algo: gostAlgo, hashMethod: "gost" });
      assert.equal(box2.resolveSignHash(kupynaCert, myHash), myHash);
    });

    it("throws EHASH on an unknown/unavailable hash value", () => {
      const box = new Box({ algo: gostAlgo });
      // typo in a per-call value
      assert.throws(() => box.resolveSignHash(gostCert, "kupina"), Box.EHASH);
      // registered OID name that has no implementation in the pool
      assert.throws(
        () => box.resolveSignHash(gostCert, "Dstu7564-256-mac"),
        Box.EHASH
      );
      // bad Box-level default
      const box2 = new Box({ algo: gostAlgo, hashMethod: "nope" });
      assert.throws(() => box2.resolveSignHash(gostCert), Box.EHASH);
    });

    it("does not throw for valid values or automatic selection", () => {
      const box = new Box({ algo: gostAlgo });
      assert.doesNotThrow(() => box.resolveSignHash(gostCert)); // auto
      assert.doesNotThrow(() => box.resolveSignHash(gostCert, "auto"));
      assert.doesNotThrow(() => box.resolveSignHash(gostCert, "kupyna"));
    });
  });
});
