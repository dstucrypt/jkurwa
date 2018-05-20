const jk = require('../lib/index.js');
const assert = require('assert');
const fs = require('fs');

describe('Certificate', function () {

    describe('parse sfs stamp', function() {
        const data = fs.readFileSync(__dirname + '/data/SFS_1.cer');
        const cert = jk.Certificate.from_asn1(data);

        it('should parse certificate from binary', ()=> {
            assert.equal(cert.format, 'x509');
            assert.equal(cert.curve.m, 257);
            assert.deepEqual(cert.curve.mod_bits, [257, 12, 0]);
            assert.deepEqual(cert.pk_data,
              ['0x2c157a5f', '0x17857f3c', '0xee0ce4a5', '0xbf03a3b', '0xcb31f667', '0x71224a5', '0x31401ac', '0xcae8dae1', '0x1']
            );
            assert.equal(cert.valid.from, 1478124000000); // UTCTime 2016-11-02 22:00:00 UTC
            assert.equal(cert.valid.to, 1541196000000); // UTCTime 2018-11-02 22:00:00 UTC
            assert.equal(cert.serial, 295234990915418097076372072606219913778474207744);
            assert.equal(cert.signatureAlgorithm, 'Dstu4145le');
            assert.equal(cert.pubkeyAlgorithm, 'Dstu4145le');
            assert.equal(cert.extension.ipn.DRFO, null);
            assert.equal(cert.extension.ipn.EDRPOU, '39292197');

            assert.equal(cert.subject.commonName, 'Державна фіскальна служба України.  ОТРИМАНО');
            assert.equal(cert.subject.organizationName, 'Державна фіскальна служба України');
            assert.equal(cert.subject.countryName, 'UA');
            assert.equal(cert.subject.localityName, 'Київ');
            assert.equal(cert.subject.serialNumber, '2122385');

            assert.equal(cert.issuer.commonName, 'Акредитований центр сертифікації ключів ІДД ДФС');
            assert.equal(cert.issuer.organizationName, 'Інформаційно-довідковий департамент ДФС');
            assert.equal(cert.issuer.organizationalUnitName, 'Управління (центр) сертифікації ключів ІДД ДФС');
            assert.equal(cert.issuer.countryName, 'UA');
            assert.equal(cert.issuer.localityName, 'Київ');
            assert.equal(cert.issuer.serialNumber, 'UA-39384476');

        });

        it('should make simple representation of certificate', function() {
            const info = cert.as_dict();
            assert.deepEqual(info.subject, {
                commonName: 'Державна фіскальна служба України.  ОТРИМАНО',
                organizationName: 'Державна фіскальна служба України',
                countryName: 'UA',
                localityName: 'Київ',
                serialNumber: '2122385',
            });
            assert.deepEqual(info.issuer, {
                commonName: 'Акредитований центр сертифікації ключів ІДД ДФС',
                organizationName: 'Інформаційно-довідковий департамент ДФС',
                organizationalUnitName: 'Управління (центр) сертифікації ключів ІДД ДФС',
                countryName: 'UA',
                localityName: 'Київ',
                serialNumber: 'UA-39384476',
            });
            assert.deepEqual(info.valid, {
                from: 1478124000000, // UTCTime 2016-11-02 22:00:00 UTC
                to: 1541196000000, // UTCTime 2018-11-02 22:00:00 UTC
            });
            assert.deepEqual(info.extension.ipn, {
                EDRPOU: '39292197',
            });
            assert.equal(info.extension.tsp, 'http://acskidd.gov.ua/services/tsp/');
            assert.equal(info.extension.ocsp, 'http://acskidd.gov.ua/services/ocsp/');
            assert.equal(info.extension.issuers, 'http://acskidd.gov.ua/download/certificates/allacskidd.p7b');
            assert.equal(info.extension.keyUsage[3], 0xC0); // bin 11
        });

        it('should serialize back', function() {
            const der = cert.to_asn1();
            assert.deepEqual(der, data);
        });

        it('should make issuer rdn', function() {
            const rdn = cert.rdnSerial();
            assert.deepEqual(
              rdn,
              '33b6cb7bf721b9ce040000009162200086e34a00' +
              '@organizationName=Інформаційно-довідковий департамент ДФС' +
              '/organizationalUnitName=Управління (центр) сертифікації ключів ІДД ДФС' +
              '/commonName=Акредитований центр сертифікації ключів ІДД ДФС' +
              '/serialNumber=UA-39384476' +
              '/countryName=UA' +
              '/localityName=Київ'
            );
        });

    });

    describe('parse minjust ca', function() {
        const data = fs.readFileSync(__dirname + '/data/CA-Justice.cer');
        const cert = jk.Certificate.from_asn1(data);

        it('should parse certificate from binary', ()=> {
            assert.equal(cert.format, 'x509');
            assert.equal(cert.curve.m, 257);
            assert.deepEqual(cert.curve.mod_bits, [257, 12, 0]);
            assert.deepEqual(cert.pk_data,
                ['0xb59265f0', '0xaaf792b8', '0xdda16518', '0x286cb42b', '0x3e1be80f', '0x5751c3ac', '0xe579a40', '0x5002f847', '0x1']
            );
            assert.equal(cert.valid.from, 1450447200000); // 2015-12-18 14:00:00
            assert.equal(cert.valid.to, 1608300000000); // UTCTime 2018-11-02 22:00:00 UTC
            assert.equal(cert.serial, 274130962303897476041362771173503318330938753024);
            assert.equal(cert.signatureAlgorithm, 'Dstu4145le');
            assert.equal(cert.pubkeyAlgorithm, 'Dstu4145le');
            assert.equal(cert.extension.ipn, null);

            assert.equal(cert.subject.commonName, 'АЦСК органів юстиції України');
            assert.equal(cert.subject.organizationName, 'ДП "НАІС"');
            assert.equal(cert.subject.organizationalUnitName, 'Акредитований центр сертифікації ключів');
            assert.equal(cert.subject.countryName, 'UA');
            assert.equal(cert.subject.localityName, 'Київ');
            assert.equal(cert.subject.serialNumber, 'UA-39787008-2015');

            assert.equal(cert.issuer.commonName, 'Центральний засвідчувальний орган');
            assert.equal(cert.issuer.organizationName, 'Міністерство юстиції України');
            assert.equal(cert.issuer.organizationalUnitName, 'Адміністратор ІТС ЦЗО');
            assert.equal(cert.issuer.countryName, 'UA');
            assert.equal(cert.issuer.localityName, 'Київ');
            assert.equal(cert.issuer.serialNumber, 'UA-00015622-2012');
        });

        it('should serialize back', function() {
            const der = cert.to_asn1();
            assert.deepEqual(der, data);
        });

        it('should make issuer rdn', function() {
            const rdn = cert.rdnSerial();
            assert.deepEqual(
              rdn,
              '3004751def2c78ae010000000100000061000000@' +
              'organizationName=Міністерство юстиції України' +
              '/organizationalUnitName=Адміністратор ІТС ЦЗО' +
              '/commonName=Центральний засвідчувальний орган' +
              '/serialNumber=UA-00015622-2012' +
              '/countryName=UA' +
              '/localityName=Київ'
            );
        });
  });

  describe('parse minjust ca (ecdsa)', function() {
        const data = fs.readFileSync(__dirname + '/data/CA-Justice-ECDSA-261217.cer');
        const cert = jk.Certificate.from_asn1(data);

        it('should parse certificate from binary', ()=> {

            assert.equal(cert.format, 'x509');
            assert.equal(cert.curve, null);
            assert.equal(cert.curve_id, 'secp256r1');

            assert.equal(cert.valid.from, 1514314260000); // 2017-12-26 18:51:00
            assert.equal(cert.valid.to, 1672080660000); // 2022-12-26 18:51:00
            assert.equal(cert.serial, 57595595825646241314308569398321717626221363200);
            assert.equal(cert.signatureAlgorithm, 'ECDSA-SHA256');
            assert.equal(cert.pubkeyAlgorithm, 'ECDSA');
            assert.equal(cert.extension.ipn, null);

            assert.equal(cert.subject.commonName, 'CA of the Justice of Ukraine');
            assert.equal(cert.subject.organizationName, 'State enterprise "NAIS"');
            assert.equal(cert.subject.organizationalUnitName, 'Certification Authority');
            assert.equal(cert.subject.countryName, 'UA');
            assert.equal(cert.subject.localityName, 'Kyiv');
            assert.equal(cert.subject.serialNumber, 'UA-39787008-1217');

            assert.equal(cert.issuer.commonName, 'Central certification authority');
            assert.equal(cert.issuer.organizationName, 'Ministry of Justice of Ukraine');
            assert.equal(cert.issuer.organizationalUnitName, 'Administrator ITS CCA');
            assert.equal(cert.issuer.countryName, 'UA');
            assert.equal(cert.issuer.localityName, 'Kyiv');
            assert.equal(cert.issuer.serialNumber, 'UA-00015622-256');
        });

        it('should serialize back', function() {
            const der = cert.to_asn1();
            assert.deepEqual(der, data);
        });

        it('should make issuer rdn', function() {
            const rdn = cert.rdnSerial();
            assert.deepEqual(
              rdn,
              'a16ad03d02fa86c010000000100000090000000' +
              '@organizationName=Ministry of Justice of Ukraine' +
              '/organizationalUnitName=Administrator ITS CCA' +
              '/commonName=Central certification authority' +
              '/serialNumber=UA-00015622-256' +
              '/countryName=UA' +
              '/localityName=Kyiv' +
              '/organizationIdentifier=NTRUA-00015622'
            );
        });
  });
});

