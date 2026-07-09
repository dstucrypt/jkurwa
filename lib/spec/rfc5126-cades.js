import asn1 from "asn1.js";
import * as rfc2560 from "./rfc2560-ocsp.js";
import * as rfc3280 from "./rfc3280.js";
import { IssuerAndSerialNumber } from "./dstszi2010.js";

/*
 * ASN.1 schema for CAdES (CMS Advanced Electronic Signatures), RFC 5126.
 *
 * These structures back the validation-data unsigned attributes that turn a
 * plain CMS signature into a long-term-verifiable one:
 *   - RevocationValues (complete-revocation-values): the actual OCSP responses
 *     (and CRLs) proving the signer cert's status at signing time.
 *   - RevocationRefs (complete-revocation-references): hashes/identifiers of
 *     those revocation values, so they can be referenced without re-embedding.
 *   - CompleteCertificateRefs (complete-certificate-references): hashes and
 *     issuer/serial of every cert in the signer's chain.
 * This is a partial model geared to the DSTU/OCSP path: CRLs are intentionally
 * left as opaque `any` since the library does not process them.
 */

// CRL bodies are not really supported; kept as opaque bytes.
const CertificateList = asn1.define("CertificateList", function () {
  // CRL is not supported really
  this.any();
});

const CrlValidatedID = asn1.define("CrlValidatedID", function () {
  // same as above
  this.any();
});

// RevocationValues: container holding the complete revocation evidence.
// crlVals [0] is unused here; ocspVals [1] carries BasicOCSPResponse values.
const RevocationValues = asn1.define("RevocationValues", function () {
  this.seq().obj(
    this.key("crlVals").optional().explicit(0).seqof(CertificateList),
    this.key("ocspVals").optional().explicit(1).seqof(rfc2560.BasicOCSPResponse)
  );
});

// OcspIdentifier: pins a referenced OCSP response by its responder ID and
// producedAt time.
const OcspIdentifier = asn1.define("OcspIdentifier", function () {
  this.seq().obj(
    this.key("ocspResponderID").use(rfc2560.ResponderID),
    this.key("producedAt").gentime()
  );
});

// OtherHashAlgAndValue: a hash algorithm OID plus hash value, used to reference
// a cert or OCSP response without embedding it (DSTU: GOST 34.311 hash).
const OtherHashAlgAndValue = asn1.define("OtherHashAlgAndValue", function () {
  this.seq().obj(
    this.key("hashAlgorithm").use(rfc3280.AlgorithmIdentifier),
    this.key("hashValue").octstr()
  );
});

// OcspResponsesID: one referenced OCSP response — its identifier plus an
// optional hash (ocspRepHash) over the response bytes.
const OcspResponsesID = asn1.define("OcspResponsesID", function () {
  this.seq().obj(
    this.key("ocspIdentifier").use(OcspIdentifier),
    this.key("ocspRepHash").optional().use(OtherHashAlgAndValue)
  );
});

const OcspListID = asn1.define("OcspListID", function () {
  this.seq().obj(this.key("ocspResponses").seqof(OcspResponsesID));
});

// CrlOcspRef: revocation references for one certificate — CRL ids [0] (unused)
// and/or OCSP ids [1].
const CrlOcspRef = asn1.define("CrlOcspRef", function () {
  this.seq().obj(
    this.key("crlids").optional().explicit(0).use(CrlValidatedID),
    this.key("ocspids").optional().explicit(1).use(OcspListID)
  );
});

// RevocationRefs (CompleteRevocationRefs): one CrlOcspRef per certificate in
// the chain. Note the exported name differs from the internal asn1 name.
const RevocationRefs = asn1.define("CompleteRevocationRefs", function () {
  this.seqof(CrlOcspRef);
});

// OtherCertID: references one chain certificate by hash plus optional
// issuer/serial.
const OtherCertID = asn1.define("OtherCertID", function () {
  this.seq().obj(
    this.key("otherCertHash").use(OtherHashAlgAndValue),
    this.key("issuerSerial").optional().use(IssuerAndSerialNumber)
  );
});

// CompleteCertificateRefs: the full set of OtherCertID references covering the
// signer's certificate chain.
const CompleteCertificateRefs = asn1.define(
  "CompleteCertificateRefs",
  function () {
    this.seqof(OtherCertID);
  }
);

export { RevocationValues, RevocationRefs, CompleteCertificateRefs };
