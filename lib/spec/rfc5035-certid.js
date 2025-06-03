import asn1 from 'asn1.js';
import * as cmp from './rfc4210-cmp.js';
import * as rfc3280 from './rfc3280.js';

/*
    ESSCertIDv2 ::=  SEQUENCE {
        hashAlgorithm           AlgorithmIdentifier
                DEFAULT {algorithm id-sha256},
        certHash                 Hash,
        issuerSerial             IssuerSerial OPTIONAL
    }

    Hash ::= OCTET STRING

    IssuerSerial ::= SEQUENCE {
        issuer                   GeneralNames,
        serialNumber             CertificateSerialNumber
    }
*/

var GeneralNames = asn1.define('GeneralNames', function() {
    this.seqof(cmp.GeneralName);
});

var IssuerSerial = asn1.define('IssuerSerial', function() {
    this.seq().obj(
        this.key('issuer').use(GeneralNames),
        this.key('serialNumber').use(rfc3280.CertificateSerialNumber)
    );
});
export { IssuerSerial };

var ESSCertIDv2 = asn1.define('ESSCertIDv2', function() {
    this.seq().obj(
        this.key('hashAlgorithm').use(rfc3280.AlgorithmIdentifier),
        this.key('certHash').octstr(),
        this.key('issuerSerial').use(IssuerSerial)
    );
});

export { ESSCertIDv2 };

var SigningCertificateV2 = asn1.define('SigningCertificateV2', function() {
    this.seq().obj(
        this.key('certs').seqof(ESSCertIDv2),
        this.key('policies').optional().any()
    );
});
SigningCertificateV2.wrap = function (cert, hash) {
    var idv2 = {
        'hashAlgorithm': {
            'algorithm': 'Gost34311',
        },
        'certHash': hash,
        'issuerSerial': {
            'issuer': [{
                type: 'directoryName',
                value: cert.tbsCertificate.issuer
            }],
            'serialNumber': cert.tbsCertificate.serialNumber,
        }
    };
    var data = {
        certs: [idv2]
    };
    return SigningCertificateV2.encode(data, 'der');
};

export { SigningCertificateV2 };
