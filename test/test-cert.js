/* eslint-env mocha */
/* eslint-disable no-underscore-dangle */
const gost89 = require("gost89");
const assert = require("assert");
const fs = require("fs");
const jk = require("../lib/index.js");
const strutil = require("../lib/util/str");

/* eslint-disable no-global-assign, no-unused-expressions */
const NOT_RANDOM_32 = Buffer.from("12345678901234567890123456789012");

global.crypto = {
  // Moch random only for testing purposes.
  // SHOULD NOT BE USED IN REAL CODE.
  getRandomValues() {
    return NOT_RANDOM_32;
  }
};
/* eslint-enable no-global-assign, no-unused-expressions */

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
    const data = fs.readFileSync(`${__dirname}/data/SFS_1.cer`);
    const cert = jk.Certificate.from_asn1(data);

    it("should parse certificate from binary", () => {
      assert.equal(cert.format, "x509");
      assert.equal(cert.curve.m, 257);
      assert.deepEqual(cert.curve.mod_bits, [257, 12, 0]);
      assert.deepEqual(cert.pk_data, [
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
      assert.equal(info.extension.tsp, "http://acskidd.gov.ua/services/tsp/");
      assert.equal(info.extension.ocsp, "http://acskidd.gov.ua/services/ocsp/");
      assert.equal(
        info.extension.issuers,
        "http://acskidd.gov.ua/download/certificates/allacskidd.p7b"
      );
      assert.equal(info.extension.keyUsage[3], 0xc0); // bin 11
    });

    it("should serialize back", () => {
      const der = cert.to_asn1();
      assert.deepEqual(der, data);
    });

    it("should serialize name to asn1", () => {
      const der = cert.name_asn1();
      assert.deepEqual(
        der.toString("hex"),
        data.slice(50, 336 + 4 + 50).toString("hex")
      );
    });

    it("should serialize (bypass cache) back", () => {
      const temp = jk.Certificate.from_asn1(data);
      delete temp._raw;
      const der = temp.to_asn1();
      assert.deepEqual(der, data);
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
    const data = fs.readFileSync(`${__dirname}/data/CA-Justice.cer`);
    const cert = jk.Certificate.from_asn1(data);

    it("should parse certificate from binary", () => {
      assert.equal(cert.format, "x509");
      assert.equal(cert.curve.m, 257);
      assert.deepEqual(cert.curve.mod_bits, [257, 12, 0]);
      assert.deepEqual(cert.pk_data, [
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
      assert.deepEqual(der, data);
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
      const temp = jk.Certificate.from_asn1(data);
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
    const data = fs.readFileSync(`${__dirname}/data/CZOROOT.cer`);

    it("should parse certificate", () => {
      const cert = jk.Certificate.from_asn1(data);
      assert.equal(cert.format, "x509");
      assert.equal(cert.signatureAlgorithm, "Dstu4145le");
      assert.equal(cert.subject.serialNumber, "UA-00015622-2012");
      assert.deepEqual(cert.issuer, cert.subject);
    });

    it("should verify validity of self-signed root", () => {
      const cert = jk.Certificate.from_asn1(data);
      assert.equal(
        cert.verifySelfSigned({
          time: 1556798940000,
          dstuHash: algo.hash
        }),
        true
      );
    });

    it("should verify validity of self-signed root (fail if messed with)", () => {
      const cert = jk.Certificate.from_asn1(data);
      cert.ob.tbsCertificate.issuer.value[0][0].value = Buffer.from("123");
      assert.equal(
        cert.verifySelfSigned({
          time: 1556798940000,
          dstuHash: algo.hash
        }),
        false
      );
    });

    it("should verify validity of self-signed root (fail if algo doesnt match)", () => {
      const cert = jk.Certificate.from_asn1(data);
      cert.signatureAlgorithm = "ECDSA";
      assert.equal(
        cert.verifySelfSigned({
          time: 1556798940000,
          dstuHash: algo.hash
        }),
        false
      );
    });

    it("should verify validity of self-signed root (fail if expired)", () => {
      const cert = jk.Certificate.from_asn1(data);
      assert.equal(
        cert.verifySelfSigned({
          time: 1700000000000,
          dstuHash: algo.hash
        }),
        false
      );
    });

    it("should verify validity of self-signed root (fail if not active yet)", () => {
      const cert = jk.Certificate.from_asn1(data);
      assert.equal(
        cert.verifySelfSigned({
          time: 1300000000000,
          dstuHash: algo.hash
        }),
        false
      );
    });
  });

  describe("parse minjust ca (ecdsa)", () => {
    const data = fs.readFileSync(
      `${__dirname}/data/CA-Justice-ECDSA-261217.cer`
    );
    const pemData = fs.readFileSync(
      `${__dirname}/data/CA-Justice-ECDSA-261217.pem`
    );
    const cert = jk.Certificate.from_asn1(data);

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
      assert.deepEqual(der, data);
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

  describe("Generated Cert", () => {
    const curve = jk.std_curve("DSTU_PB_257");
    const priv = jk.Priv.from_asn1(
      fs.readFileSync(`${__dirname}/data/PRIV1.cer`),
    );
    const privEncE54B = jk.Priv.from_asn1(
      fs.readFileSync(`${__dirname}/data/KeyE54B.cer`),
    );
    const privEnc6929 = jk.Priv.from_asn1(
      fs.readFileSync(`${__dirname}/data/Key6929.cer`)
    );
    const privEnc40A0 = jk.Priv.from_asn1(
      fs.readFileSync(`${__dirname}/data/Key40A0.cer`),
    );

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
      assert.deepEqual(
        fs.readFileSync(`${__dirname}/data/SELF_SIGNED1.cer`),
        data
      );
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
      assert.deepEqual(
        fs.readFileSync(`${__dirname}/data/SELF_SIGNED_ENC_40A0.cer`),
        data
      );
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
      assert.deepEqual(
        fs.readFileSync(`${__dirname}/data/SELF_SIGNED_ENC_6929.cer`),
        data
      );
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
      assert.deepEqual(
        fs.readFileSync(`${__dirname}/data/SELF_SIGNED_ENC_E54B.cer`),
        data
      );
    });

    it("should check that self-signed cert is valid", () => {
      const data = fs.readFileSync(`${__dirname}/data/SELF_SIGNED1.cer`);
      const cert = jk.Certificate.from_asn1(data);

      assert.equal(
        cert.verifySelfSigned({ time: 1550000000000, dstuHash: algo.hash }),
        true
      );
    });
  });
});
