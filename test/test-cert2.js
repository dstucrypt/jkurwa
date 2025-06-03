import { describe, it } from "vitest";
import gost89 from "gost89";
import assert from "assert";
import * as jk from "../lib/index.js";
import { loadAsset, loadCert, assertEqualSaved } from "./utils.js";

describe("Certificate", () => {
  const algo = gost89.compat.algos();

  describe("parse minjust ca (ecdsa)", () => {
    const data = loadAsset("CA-Justice-ECDSA-261217.cer");
    const pemData = loadAsset("CA-Justice-ECDSA-261217.pem");
    const cert = loadCert("CA-Justice-ECDSA-261217.cer");

    it("should parse certificate from binary", () => {
      assert.equal(cert.format, "x509");
      assert.equal(cert.curve, null);
      assert.equal(cert.curve_id, "secp256r1");

      assert.equal(cert.valid.from, 1514314260000); // 2017-12-26 18:51:00
      assert.equal(cert.valid.to, 1672080660000); // 2022-12-26 18:51:00
      assert.equal(
        cert.serial,
        57595595825646241314308569398321717626221363200
      );
      assert.equal(cert.signatureAlgorithm, "ECDSA-SHA256");
      assert.equal(cert.pubkeyAlgorithm, "ECDSA");
      assert.equal(cert.extension.ipn, null);

      assert.equal(cert.subject.commonName, "CA of the Justice of Ukraine");
      assert.equal(cert.subject.organizationName, 'State enterprise "NAIS"');
      assert.equal(
        cert.subject.organizationalUnitName,
        "Certification Authority"
      );
      assert.equal(cert.subject.countryName, "UA");
      assert.equal(cert.subject.localityName, "Kyiv");
      assert.equal(cert.subject.serialNumber, "UA-39787008-1217");

      assert.equal(cert.issuer.commonName, "Central certification authority");
      assert.equal(
        cert.issuer.organizationName,
        "Ministry of Justice of Ukraine"
      );
      assert.equal(cert.issuer.organizationalUnitName, "Administrator ITS CCA");
      assert.equal(cert.issuer.countryName, "UA");
      assert.equal(cert.issuer.localityName, "Kyiv");
      assert.equal(cert.issuer.serialNumber, "UA-00015622-256");
    });

    it("should parse certificate from PEM", () => {
      const pemCert = jk.Certificate.from_pem(pemData);
      assert.deepEqual(pemCert, cert);
    });

    it("should serialize back", () => {
      const der = cert.to_asn1();
      assertEqualSaved(der, "CA-Justice-ECDSA-261217.cer");
    });

    it("should serialize to PEM", () => {
      const pem = cert.to_pem();
      assert.deepEqual(pem, pemData.toString().trim());
    });

    it("should make issuer rdn", () => {
      const rdn = cert.rdnSerial();
      assert.deepEqual(
        rdn,
        "a16ad03d02fa86c010000000100000090000000" +
          "@organizationName=Ministry of Justice of Ukraine" +
          "/organizationalUnitName=Administrator ITS CCA" +
          "/commonName=Central certification authority" +
          "/serialNumber=UA-00015622-256" +
          "/countryName=UA" +
          "/localityName=Kyiv" +
          "/organizationIdentifier=NTRUA-00015622"
      );
    });
  });
});
