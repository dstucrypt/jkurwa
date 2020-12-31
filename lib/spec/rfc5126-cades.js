const asn1 = require("asn1.js");
const rfc2560 = require("./rfc2560-ocsp.js");
const rfc3280 = require("./rfc3280.js");
const { IssuerAndSerialNumber } = require("./dstszi2010.js");

const CertificateList = asn1.define("CertificateList", function() {
  // CRL is not supported really
  this.any();
});

const CrlValidatedID = asn1.define("CrlValidatedID", function() {
  // same as above
  this.any();
});

const RevocationValues = asn1.define("RevocationValues", function() {
  this.seq().obj(
    this.key("crlVals")
      .optional()
      .explicit(0)
      .seqof(CertificateList),
    this.key("ocspVals")
      .optional()
      .explicit(1)
      .seqof(rfc2560.BasicOCSPResponse)
  );
});

const OcspIdentifier = asn1.define("OcspIdentifier", function() {
  this.seq().obj(
    this.key("ocspResponderID").use(rfc2560.ResponderID),
    this.key("producedAt").gentime()
  );
});

const OtherHashAlgAndValue = asn1.define("OtherHashAlgAndValue", function() {
  this.seq().obj(
    this.key("hashAlgorithm").use(rfc3280.AlgorithmIdentifier),
    this.key("hashValue").octstr()
  );
});

const OcspResponsesID = asn1.define("OcspResponsesID", function() {
  this.seq().obj(
    this.key("ocspIdentifier").use(OcspIdentifier),
    this.key("ocspRepHash")
      .optional()
      .use(OtherHashAlgAndValue)
  );
});

const OcspListID = asn1.define("OcspListID", function() {
  this.seq().obj(this.key("ocspResponses").seqof(OcspResponsesID));
});

const CrlOcspRef = asn1.define("CrlOcspRef", function() {
  this.seq().obj(
    this.key("crlids")
      .optional()
      .explicit(0)
      .use(CrlValidatedID),
    this.key("ocspids")
      .optional()
      .explicit(1)
      .use(OcspListID)
  );
});

const RevocationRefs = asn1.define("CompleteRevocationRefs", function() {
  this.seqof(CrlOcspRef);
});

const OtherCertID = asn1.define("OtherCertID", function() {
  this.seq().obj(
    this.key("otherCertHash").use(OtherHashAlgAndValue),
    this.key("issuerSerial")
      .optional()
      .use(IssuerAndSerialNumber)
  );
});

const CompleteCertificateRefs = asn1.define(
  "CompleteCertificateRefs",
  function() {
    this.seqof(OtherCertID);
  }
);

module.exports = { RevocationValues, RevocationRefs, CompleteCertificateRefs };
