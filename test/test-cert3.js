import gost89 from "gost89";
import assert from "assert";
import * as jk from "../lib/index.js";
import { loadPriv, loadCert, assertEqualSaved } from "./utils.js";

describe("Certificate", () => {
  const algo = gost89.compat.algos();

  describe("Generated Cert", () => {
    const curve = jk.std_curve("DSTU_PB_257");
    const priv = loadPriv("PRIV1.cer");
    const privEncE54B = loadPriv("KeyE54B.cer");
    const privEnc6929 = loadPriv("Key6929.cer");
    const privEnc40A0 = loadPriv("Key40A0.cer");

    it("should generate and self-sign a cert", () => {
      const name = {
        organizationName: "Very Much CA",
        serialNumber: "UA-99999999",
        localityName: "Wakanda"
      };
      const serial = 14799991119 << 12; // eslint-disable-line no-bitwise
      const cert = jk.Certificate.signCert({
        privkey: priv,
        hash: algo.hash,

        certData: {
          serial,
          issuer: name,
          subject: name,
          valid: { from: 1500000000000, to: 1700000000000 },
          usage: "\x03\x02\x06\xC0"
        }
      });
      const data = cert.as_asn1();
      assertEqualSaved(data, "SELF_SIGNED1.cer");
    });

    it("should generate and self-sign encryption cert 40A0", () => {
      const name = {
        organizationName: "Very Much CA",
        serialNumber: "UA-99999999",
        localityName: "Wakanda"
      };
      const serial = 99991119 << 12; // eslint-disable-line no-bitwise
      const cert = jk.Certificate.signCert({
        privkey: privEnc40A0,
        hash: algo.hash,

        certData: {
          serial,
          issuer: name,
          subject: name,
          valid: { from: 1500000000000, to: 1700000000000 },
          usage: "\x03\x02\x03\x08"
        }
      });
      const data = cert.as_asn1();
      assertEqualSaved(data, "SELF_SIGNED_ENC_40A0.cer");
    });

    it("should generate and self-sign encryption cert 6929", () => {
      const name = {
        organizationName: "Very Much CA",
        serialNumber: "UA-99999991",
        localityName: "Wakanda"
      };
      const serial = 99991111 << 12; // eslint-disable-line no-bitwise
      const cert = jk.Certificate.signCert({
        privkey: privEnc6929,
        hash: algo.hash,

        certData: {
          serial,
          issuer: name,
          subject: name,
          valid: { from: 1500000000000, to: 1700000000000 },
          usage: "\x03\x02\x03\x08"
        }
      });
      const data = cert.as_asn1();
      assertEqualSaved(data, "SELF_SIGNED_ENC_6929.cer");
    });

    it("should generate and self-sign encryption cert E54B", () => {
      const name = {
        organizationName: "Very Much CA",
        serialNumber: "UA-99999999",
        localityName: "Wakanda"
      };
      const serial = 14799991119 << 12; // eslint-disable-line no-bitwise
      const cert = jk.Certificate.signCert({
        privkey: privEncE54B,
        hash: algo.hash,

        certData: {
          serial,
          issuer: name,
          subject: name,
          valid: { from: 1500000000000, to: 1700000000000 },
          usage: "\x03\x02\x03\x08"
        }
      });
      const data = cert.as_asn1();
      assertEqualSaved(data, "SELF_SIGNED_ENC_E54B.cer");
    });

    it("should check that self-signed cert is valid", () => {
      const cert = loadCert("SELF_SIGNED1.cer");

      assert.equal(
        cert.verifySelfSigned(
          { time: 1550000000000 },
          { Dstu4145le: algo.hash }
        ),
        true
      );
    });
  });
});
