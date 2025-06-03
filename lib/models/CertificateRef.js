import { IssuerAndSerialNumber } from "../spec/dstszi2010.js";
import * as cades from "../spec/rfc5126-cades.js";

class CertificateRef {
  constructor(ob) {
    this.ob = ob;
  }
}

CertificateRef.fromCert = function(cert, hashFn) {
  return new CertificateRef({
    otherCertHash: {
      hashAlgorithm: {
        algorithm: hashFn.algo || "Gost34311"
      },
      hashValue: hashFn(cert.to_asn1())
    },
    issuerSerial: cert.nameSerial()
  });
};

CertificateRef.toCades = function(list) {
  return cades.CompleteCertificateRefs.encode(list.map(iter => iter.ob), "der");
};

export default CertificateRef;
