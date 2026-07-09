/*
 * CertificateRef - CAdES CompleteCertificateRefs entry.
 *
 * Represents a single OtherCertID (RFC 5126 / CAdES) that references a
 * certificate by its hash and issuer/serial, used when building the
 * complete-certificate-references attribute of a CAdES signature.
 */
import * as cades from "../spec/rfc5126-cades.js";

class CertificateRef {
  /**
   * @param {Object} ob Decoded OtherCertID-shaped object.
   */
  constructor(ob) {
    this.ob = ob;
  }

  /**
   * Build a reference to a certificate from the certificate itself.
   * @param {Object} cert Certificate (provides to_asn1() and nameSerial()).
   * @param {Function} hashFn Hash function; hashFn.algo names the algorithm,
   *   defaulting to the Ukrainian GOST 34.311 ("Gost34311").
   * @returns {CertificateRef} Reference carrying the cert hash and issuer info.
   */
  static fromCert(cert, hashFn) {
    return new CertificateRef({
      otherCertHash: {
        hashAlgorithm: {
          algorithm: hashFn.algo || "Gost34311"
        },
        // Hash is taken over the certificate's DER encoding.
        hashValue: hashFn(cert.to_asn1())
      },
      issuerSerial: cert.nameSerial()
    });
  }

  /**
   * DER-encode a list of references as a CAdES CompleteCertificateRefs.
   * @param {Array<CertificateRef>} list References to encode.
   * @returns {Buffer} DER-encoded CompleteCertificateRefs.
   */
  static toCades(list) {
    return cades.CompleteCertificateRefs.encode(
      list.map(iter => iter.ob),
      "der"
    );
  }
}

export default CertificateRef;
