import asn1 from "asn1.js";
import * as cmp from "./rfc4210-cmp.js";
import * as rfc3280 from "./rfc3280.js";

/*
 * ASN.1 schema for the ESS signing-certificate v2 attribute, RFC 5035.
 *
 * SigningCertificateV2 is a CMS signed attribute that binds a signature to the
 * exact signer certificate by carrying a hash of that certificate (ESSCertIDv2)
 * plus its issuer/serial. It prevents certificate-substitution attacks. This
 * module builds the attribute used inside DSTU 4145 CAdES signatures, where the
 * certificate hash defaults to GOST 34.311 ("Gost34311") rather than SHA-256.
 */

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

var GeneralNames = asn1.define("GeneralNames", function () {
  this.seqof(cmp.GeneralName);
});

// IssuerSerial: identifies the referenced certificate by its issuer name(s)
// and serial number, disambiguating the certHash carried in ESSCertIDv2.
var IssuerSerial = asn1.define("IssuerSerial", function () {
  this.seq().obj(
    this.key("issuer").use(GeneralNames),
    this.key("serialNumber").use(rfc3280.CertificateSerialNumber)
  );
});
export { IssuerSerial };

// ESSCertIDv2: hash of the signer certificate (certHash) plus its
// AlgorithmIdentifier and optional IssuerSerial. Note that although RFC 5035
// makes hashAlgorithm DEFAULT id-sha256, this schema always encodes it
// explicitly (the wrap() helper supplies Gost34311 for DSTU).
var ESSCertIDv2 = asn1.define("ESSCertIDv2", function () {
  this.seq().obj(
    this.key("hashAlgorithm").use(rfc3280.AlgorithmIdentifier),
    this.key("certHash").octstr(),
    this.key("issuerSerial").use(IssuerSerial)
  );
});

export { ESSCertIDv2 };

// SigningCertificateV2: the signed-attribute value itself — a sequence of
// ESSCertIDv2 (normally just the signer cert) and optional policy info.
var SigningCertificateV2 = asn1.define("SigningCertificateV2", function () {
  this.seq().obj(
    this.key("certs").seqof(ESSCertIDv2),
    this.key("policies").optional().any()
  );
});
/**
 * Build a DER-encoded SigningCertificateV2 attribute value for a single signer
 * certificate.
 *
 * @param {Object} cert  Parsed certificate; cert.tbsCertificate.issuer and
 *   .serialNumber are used to fill the ESSCertIDv2 issuerSerial.
 * @param {Buffer} hash  Precomputed hash of the certificate (certHash).
 * @param {string} [algo="Gost34311"]  Hash AlgorithmIdentifier name; defaults
 *   to the DSTU GOST 34.311 hash rather than SHA-256.
 * @returns {Buffer} DER encoding of the SigningCertificateV2 structure.
 */
SigningCertificateV2.wrap = function (cert, hash, algo) {
  var idv2 = {
    hashAlgorithm: {
      algorithm: algo || "Gost34311"
    },
    certHash: hash,
    issuerSerial: {
      issuer: [
        {
          type: "directoryName",
          value: cert.tbsCertificate.issuer
        }
      ],
      serialNumber: cert.tbsCertificate.serialNumber
    }
  };
  var data = {
    certs: [idv2]
  };
  return SigningCertificateV2.encode(data, "der");
};

export { SigningCertificateV2 };
