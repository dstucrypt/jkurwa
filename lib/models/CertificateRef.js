import * as cades from "../spec/rfc5126-cades.js";

class CertificateRef {
  constructor(ob) {
    this.ob = ob;
  }

  static fromCert(cert, hashFn) {
    return new CertificateRef({
      otherCertHash: {
        hashAlgorithm: {
          algorithm: hashFn.algo || "Gost34311"
        },
        hashValue: hashFn(cert.to_asn1())
      },
      issuerSerial: cert.nameSerial()
    });
  }

  static toCades(list) {
    return cades.CompleteCertificateRefs.encode(
      list.map(iter => iter.ob),
      "der"
    );
  }
}

export default CertificateRef;
