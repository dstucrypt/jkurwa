const asn1 = require("asn1.js");
const { BasicOCSPResponse } = require("./rfc2560-ocsp.js");

const CertificateList = asn1.define("CertificateList", function() {
  // CRL is not supported really
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
      .seqof(BasicOCSPResponse)
  );
});

module.exports = { RevocationValues };
