import gost89 from "gost89";
import assert from "assert";
import * as strutil from "../lib/util/str.js";
import { loadAsset, loadCert, assertEqualSaved } from "./utils.js";

function repeate(inputStr, times) {
  let ret = "";
  let left = times;
  while (left > 0) {
    ret += inputStr;
    left -= 1;
  }
  return ret;
}

function u(input) {
  return strutil.encodeUtf8Str(input, "der");
}

describe("Certificate", () => {
  const algo = gost89.compat.algos();
  describe("parse sfs stamp", () => {
    const cert = loadCert("SFS_1.cer");

    it("should parse certificate from binary", () => {
      assert.equal(cert.format, "x509");
      assert.equal(cert.curve.m, 257);
      assert.deepEqual(Array.from(cert.curve.mod_bits), [257, 12, 0]);
      assert.deepEqual(Array.from(cert.pk_data), [
        "0x2c157a5f",
        "0x17857f3c",
        "0xee0ce4a5",
        "0xbf03a3b",
        "0xcb31f667",
        "0x71224a5",
        "0x31401ac",
        "0xcae8dae1",
        "0x1"
      ]);
      assert.equal(cert.valid.from, 1478124000000); // UTCTime 2016-11-02 22:00:00 UTC
      assert.equal(cert.valid.to, 1541196000000); // UTCTime 2018-11-02 22:00:00 UTC
      assert.equal(
        cert.serial,
        295234990915418097076372072606219913778474207744
      );
      assert.equal(cert.signatureAlgorithm, "Dstu4145le");
      assert.equal(cert.pubkeyAlgorithm, "Dstu4145le");
      assert.equal(cert.extension.ipn.DRFO, null);
      assert.equal(cert.extension.ipn.EDRPOU, "39292197");

      assert.equal(
        cert.subject.commonName,
        "Державна фіскальна служба України.  ОТРИМАНО"
      );
      assert.equal(
        cert.subject.organizationName,
        "Державна фіскальна служба України"
      );
      assert.equal(cert.subject.countryName, "UA");
      assert.equal(cert.subject.localityName, "Київ");
      assert.equal(cert.subject.serialNumber, "2122385");

      assert.equal(
        cert.issuer.commonName,
        "Акредитований центр сертифікації ключів ІДД ДФС"
      );
      assert.equal(
        cert.issuer.organizationName,
        "Інформаційно-довідковий департамент ДФС"
      );
      assert.equal(
        cert.issuer.organizationalUnitName,
        "Управління (центр) сертифікації ключів ІДД ДФС"
      );
      assert.equal(cert.issuer.countryName, "UA");
      assert.equal(cert.issuer.localityName, "Київ");
      assert.equal(cert.issuer.serialNumber, "UA-39384476");
    });

    it("should make simple representation of certificate", () => {
      const info = cert.as_dict();
      assert.deepEqual(info.subject, {
        commonName: "Державна фіскальна служба України.  ОТРИМАНО",
        organizationName: "Державна фіскальна служба України",
        countryName: "UA",
        localityName: "Київ",
        serialNumber: "2122385"
      });
      assert.deepEqual(info.issuer, {
        commonName: "Акредитований центр сертифікації ключів ІДД ДФС",
        organizationName: "Інформаційно-довідковий департамент ДФС",
        organizationalUnitName:
          "Управління (центр) сертифікації ключів ІДД ДФС",
        countryName: "UA",
        localityName: "Київ",
        serialNumber: "UA-39384476"
      });
      assert.deepEqual(info.valid, {
        from: 1478124000000, // UTCTime 2016-11-02 22:00:00 UTC
        to: 1541196000000 // UTCTime 2018-11-02 22:00:00 UTC
      });
      assert.deepEqual(info.extension.ipn, {
        EDRPOU: "39292197"
      });

      assert.deepEqual(info.extension.subjectInfoAccess, {
        id: "tsp",
        link: "http://acskidd.gov.ua/services/tsp/"
      });
      assert.deepEqual(info.extension.authorityInfoAccess, {
        id: "ocsp",
        issuers: "http://acskidd.gov.ua/download/certificates/allacskidd.p7b",
        link: "http://acskidd.gov.ua/services/ocsp/"
      });
      assert.deepEqual(info.usage, { sign: true, encrypt: false });
    });

    it("should serialize back", () => {
      const der = cert.to_asn1();
      assertEqualSaved(der, "SFS_1.cer");
    });

    it("should serialize name to asn1", () => {
      const der = cert.name_asn1();
      const data = loadAsset("SFS_1.cer");
      assert.deepEqual(
        der.toString("hex"),
        data.slice(50, 336 + 4 + 50).toString("hex")
      );
    });

    it("should serialize (bypass cache) back", () => {
      const temp = loadCert("SFS_1.cer");
      delete temp._raw;
      const der = temp.to_asn1();
      assertEqualSaved(der, "SFS_1.cer");
    });

    it("should make issuer rdn", () => {
      const rdn = cert.rdnSerial();
      assert.deepEqual(
        rdn,
        "33b6cb7bf721b9ce040000009162200086e34a00" +
          "@organizationName=Інформаційно-довідковий департамент ДФС" +
          "/organizationalUnitName=Управління (центр) сертифікації ключів ІДД ДФС" +
          "/commonName=Акредитований центр сертифікації ключів ІДД ДФС" +
          "/serialNumber=UA-39384476" +
          "/countryName=UA" +
          "/localityName=Київ"
      );
    });
  });

  describe("parse minjust ca", () => {
    const cert = loadCert("CA-Justice.cer");

    it("should parse certificate from binary", () => {
      assert.equal(cert.format, "x509");
      assert.equal(cert.curve.m, 257);
      assert.deepEqual(Array.from(cert.curve.mod_bits), [257, 12, 0]);
      assert.deepEqual(Array.from(cert.pk_data), [
        "0xb59265f0",
        "0xaaf792b8",
        "0xdda16518",
        "0x286cb42b",
        "0x3e1be80f",
        "0x5751c3ac",
        "0xe579a40",
        "0x5002f847",
        "0x1"
      ]);
      assert.equal(cert.valid.from, 1450447200000); // 2015-12-18 14:00:00
      assert.equal(cert.valid.to, 1608300000000); // UTCTime 2018-11-02 22:00:00 UTC
      assert.equal(
        cert.serial,
        274130962303897476041362771173503318330938753024
      );
      assert.equal(cert.signatureAlgorithm, "Dstu4145le");
      assert.equal(cert.pubkeyAlgorithm, "Dstu4145le");
      assert.equal(cert.extension.ipn, null);

      assert.equal(cert.subject.commonName, "АЦСК органів юстиції України");
      assert.equal(cert.subject.organizationName, 'ДП "НАІС"');
      assert.equal(
        cert.subject.organizationalUnitName,
        "Акредитований центр сертифікації ключів"
      );
      assert.equal(cert.subject.countryName, "UA");
      assert.equal(cert.subject.localityName, "Київ");
      assert.equal(cert.subject.serialNumber, "UA-39787008-2015");

      assert.equal(cert.issuer.commonName, "Центральний засвідчувальний орган");
      assert.equal(
        cert.issuer.organizationName,
        "Міністерство юстиції України"
      );
      assert.equal(cert.issuer.organizationalUnitName, "Адміністратор ІТС ЦЗО");
      assert.equal(cert.issuer.countryName, "UA");
      assert.equal(cert.issuer.localityName, "Київ");
      assert.equal(cert.issuer.serialNumber, "UA-00015622-2012");
    });

    it("should serialize back", () => {
      const der = cert.to_asn1();
      assertEqualSaved(der, "CA-Justice.cer");
    });

    it("should make issuer rdn", () => {
      const rdn = cert.rdnSerial();
      assert.deepEqual(
        rdn,
        "3004751def2c78ae010000000100000061000000@" +
          "organizationName=Міністерство юстиції України" +
          "/organizationalUnitName=Адміністратор ІТС ЦЗО" +
          "/commonName=Центральний засвідчувальний орган" +
          "/serialNumber=UA-00015622-2012" +
          "/countryName=UA" +
          "/localityName=Київ"
      );
    });

    it("should make issuer rdn for really long orgname", () => {
      const longName = repeate("ЦЗО!", 100);
      const temp = loadCert("CA-Justice.cer");
      temp.ob.tbsCertificate.issuer.value[0][0].value = u(longName);

      const rdn = temp.rdnSerial();
      assert.deepEqual(
        rdn,
        "3004751def2c78ae010000000100000061000000@" +
          `organizationName=${longName}` +
          "/organizationalUnitName=Адміністратор ІТС ЦЗО" +
          "/commonName=Центральний засвідчувальний орган" +
          "/serialNumber=UA-00015622-2012" +
          "/countryName=UA" +
          "/localityName=Київ"
      );
    });
  });

  describe("parse CZO root", () => {
    const cert = loadCert("CZOROOT.cer");

    it("should parse certificate", () => {
      assert.equal(cert.format, "x509");
      assert.equal(cert.signatureAlgorithm, "Dstu4145le");
      assert.equal(cert.subject.serialNumber, "UA-00015622-2012");
      assert.deepEqual(cert.issuer, cert.subject);
    });

    it("should verify validity of self-signed root", () => {
      assert.equal(
        cert.verifySelfSigned(
          {
            time: 1556798940000
          },
          { Dstu4145le: algo.hash }
        ),
        true
      );
    });

    it("should verify validity of self-signed root (fail if messed with)", () => {
      const temp = loadCert("CZOROOT.cer");
      temp.ob.tbsCertificate.issuer.value[0][0].value = Buffer.from("123");
      assert.equal(
        temp.verifySelfSigned(
          {
            time: 1556798940000
          },
          { Dstu4145le: algo.hash }
        ),
        false
      );
    });

    it("should verify validity of self-signed root (fail if algo doesnt match)", () => {
      const temp = loadCert("CZOROOT.cer");
      temp.signatureAlgorithm = "ECDSA";
      assert.equal(
        temp.verifySelfSigned(
          {
            time: 1556798940000
          },
          { Dstu4145le: algo.hash }
        ),
        false
      );
    });

    it("should verify validity of self-signed root (fail if expired)", () => {
      assert.equal(
        cert.verifySelfSigned(
          {
            time: 1700000000000
          },
          { Dstu4145le: algo.hash }
        ),
        false
      );
    });

    it("should verify validity of self-signed root (fail if not active yet)", () => {
      assert.equal(
        cert.verifySelfSigned(
          {
            time: 1300000000000
          },
          { Dstu4145le: algo.hash }
        ),
        false
      );
    });
  });
});
