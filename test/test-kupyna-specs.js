import { describe, it, expect } from "vitest";
import * as jk from "../lib/index.js";
import { obj_parse } from "../lib/spec/pbes.js";
import { SigningCertificateV2 } from "../lib/spec/rfc5035-certid.js";
import { loadCert } from "./utils.js";

// These tests cover the parts of the Kupyna port that the CAdES fixtures do not
// reach: the PBES2 profile dispatch and the hashAlgorithm recorded inside the
// signing-certificate-v2 attribute.  They build their inputs in memory, so they
// stay fast even on the slow riscv64 box the suite normally runs on.

function pbes2Asn1({ kdf, enc, iv, dke, saltLength = 32 }) {
  return {
    contentEncryptionAlgorithm: {
      algorithm: "PBES2",
      parameters: {
        type: "params",
        value: {
          keyDerivationFunc: {
            id: "PBKDF2",
            params: {
              salt: Buffer.alloc(saltLength),
              cycles: { toNumber: () => 10000 },
              hash: { algorithm: kdf }
            }
          },
          encryptionScheme: {
            algorithm: enc,
            parameters: {
              type: "params",
              value: dke ? { iv, dke } : { iv }
            }
          }
        }
      }
    },
    encryptedContent: Buffer.from("00112233", "hex")
  };
}

describe("PBES2 profile dispatch", () => {
  it("parses the legacy GOST profile", () => {
    const store = obj_parse(
      pbes2Asn1({
        kdf: "Gost34311-hmac",
        enc: "Gost28147-cfb",
        iv: Buffer.alloc(8),
        dke: Buffer.alloc(64)
      })
    );

    expect(store.kdf).toBe("Gost34311-hmac");
    expect(store.enc).toBe("Gost28147-cfb");
    expect(store.iv.length).toBe(8);
    expect(store.sbox.length).toBe(64);
    expect(store.iters).toBe(10000);
  });

  it("parses the Kupyna/Kalyna profile", () => {
    const store = obj_parse(
      pbes2Asn1({
        kdf: "Dstu7564mac-256",
        enc: "Dstu7624cbc-256",
        iv: Buffer.alloc(32)
      })
    );

    expect(store.kdf).toBe("Dstu7564mac-256");
    expect(store.enc).toBe("Dstu7624cbc-256");
    expect(store.iv.length).toBe(32);
    expect(store.sbox).toBeUndefined();
  });

  it("rejects a KDF/cipher pair that belongs to different profiles", () => {
    expect(() =>
      obj_parse(
        pbes2Asn1({
          kdf: "Gost34311-hmac",
          enc: "Dstu7624cbc-256",
          iv: Buffer.alloc(32)
        })
      )
    ).toThrow(/does not match KDF/);
  });

  it("rejects an unknown KDF", () => {
    expect(() =>
      obj_parse(
        pbes2Asn1({
          kdf: "Dstu7564mac-512",
          enc: "Dstu7624cbc-256",
          iv: Buffer.alloc(32)
        })
      )
    ).toThrow(/Unknown cipher/);
  });

  it("rejects a wrong IV length", () => {
    expect(() =>
      obj_parse(
        pbes2Asn1({
          kdf: "Dstu7564mac-256",
          enc: "Dstu7624cbc-256",
          iv: Buffer.alloc(16)
        })
      )
    ).toThrow(/IV len/);
  });
});

describe("SigningCertificateV2 hashName", () => {
  const cert = loadCert("CZOROOT.cer");

  it("records the digest that produced the certificate hash", () => {
    const hash = Buffer.alloc(32, 7);
    const encoded = SigningCertificateV2.wrap(
      cert.ob,
      hash,
      "Dstu7564-256"
    );
    const decoded = SigningCertificateV2.decode(encoded, "der");

    expect(decoded.certs[0].hashAlgorithm.algorithm).toBe("Dstu7564-256");
  });

  it("keeps the historical GOST default when no name is passed", () => {
    const encoded = SigningCertificateV2.wrap(cert.ob, Buffer.alloc(32));
    const decoded = SigningCertificateV2.decode(encoded, "der");

    expect(decoded.certs[0].hashAlgorithm.algorithm).toBe("Gost34311");
  });
});

describe("Box algorithm table", () => {
  it("works when only a hashes map is supplied", () => {
    const box = new jk.Box({
      algo: { hashes: { Gost34311: () => Buffer.alloc(32) } }
    });

    expect(box.getHashAlgo("Gost34311").algo).toBe("Gost34311");
    expect(() => box.getHashAlgo("Dstu7564-256")).toThrow(
      /No hash implementation/
    );
  });

  it("promotes the legacy single algo.hash into the map", () => {
    const fn = () => Buffer.alloc(32);
    const box = new jk.Box({ algo: { hash: fn } });

    expect(box.getHashAlgo("Gost34311").algo).toBe("Gost34311");
    expect(box.getHashAlgo("Dstu4145le").algo).toBe("Dstu4145le");
  });
});

describe("Kupyna curve names", () => {
  it("resolves the KU aliases whose parameters are bundled", () => {
    expect(jk.Curve.from_id("DSTU_PB_191_KU").m).toBe(191);
    expect(jk.Curve.from_id("DSTU_PB_257_KU").m).toBe(257);
    expect(jk.Curve.from_id("DSTU_PB_431_KU").m).toBe(431);
  });

  it("throws for a KU name without bundled parameters", () => {
    expect(() => jk.Curve.from_id("DSTU_PB_163_KU")).toThrow();
  });
});
