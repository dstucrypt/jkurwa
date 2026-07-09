/*
 * ASN.1 schema for X.509 v3 certificates per RFC 3280 (PKIX), specialised for
 * Ukrainian PKI.
 *
 * This module models Certificate / TBSCertificate and the surrounding X.501
 * naming (Name, RDNSequence, AttributeTypeAndValue), validity, extensions and
 * the SubjectPublicKeyInfo, all built with asn1.js `define()`. Compared to a
 * plain RFC 3280 profile it registers the DSTU national algorithm OIDs
 * (DSTU 4145 signatures, GOST 34.311 / DSTU 7564 "Kupyna" hashes,
 * GOST 28147 cipher) in ALGORITHMS_IDS so Ukrainian certificates parse, and it
 * lets callers plug in public-key parameter parsers via injectPubAlgo(). These
 * definitions are consumed by the DSTSZI-2010 CMS and CMP schemas in this
 * directory.
 */
import asn1 from "asn1.js";

// CRL revocation reason code (RFC 3280 s5.3.1), used inside the CRLReason
// certificate/CRL entry extension.
var CRLReason = asn1.define("CRLReason", function () {
  this.enum({
    0: "unspecified",
    1: "keyCompromise",
    2: "CACompromise",
    3: "affiliationChanged",
    4: "superseded",
    5: "cessationOfOperation",
    6: "certificateHold",
    8: "removeFromCRL",
    9: "privilegeWithdrawn",
    10: "AACompromise"
  });
});
export { CRLReason };

// Algorithm OID lookup table. The 1.2.804.2.1.1.1.* arc is the Ukrainian
// DSTU/GOST national suite (hashes, cipher, DSTU 4145 EC signatures, and the
// combined signature-with-hash OIDs used as certificate signatureAlgorithm);
// the 1.2.840.10045.* entries are the international ECDSA equivalents. This
// table is shared by the CMS and CMP schemas for resolving algorithm names.
var ALGORITHMS_IDS = {
  "1 2 804 2 1 1 1 1 2 1": "Gost34311",
  "1 2 804 2 1 1 1 1 1 1 3": "Gost28147-cfb",
  "1 2 804 2 1 1 1 1 3 4": "dhSinglePass-cofactorDH-gost34311kdf",
  "1 2 804 2 1 1 1 1 1 1 5": "Gost28147-cfb-wrap",
  "1 2 804 2 1 1 1 1 1 2": "Gost34311-hmac",
  "1 2 804 2 1 1 1 1 3 1 1": "Dstu4145le",
  // DSTU 7564:2014 (Kupyna) hash function family
  "1 2 804 2 1 1 1 1 2 2 1": "Dstu7564-256",
  "1 2 804 2 1 1 1 1 2 2 2": "Dstu7564-384",
  "1 2 804 2 1 1 1 1 2 2 3": "Dstu7564-512",
  "1 2 804 2 1 1 1 1 2 2 4": "Dstu7564-256-mac",
  "1 2 804 2 1 1 1 1 2 2 5": "Dstu7564-384-mac",
  "1 2 804 2 1 1 1 1 2 2 6": "Dstu7564-512-mac",
  // DSTU 4145 signature with Kupyna hash (certificate signatureAlgorithm)
  "1 2 804 2 1 1 1 1 3 6 1": "Dstu4145le-Dstu7564-256",
  "1 2 804 2 1 1 1 1 3 6 1 1": "Dstu4145le-Dstu7564-256-pb",
  "1 2 804 2 1 1 1 1 3 6 2": "Dstu4145le-Dstu7564-384",
  "1 2 804 2 1 1 1 1 3 6 2 1": "Dstu4145le-Dstu7564-384-pb",
  "1 2 804 2 1 1 1 1 3 6 3": "Dstu4145le-Dstu7564-512",
  "1 2 804 2 1 1 1 1 3 6 3 1": "Dstu4145le-Dstu7564-512-pb",
  "1 2 840 10045 2 1": "ECDSA",
  "1 2 840 10045 4 3 2": "ECDSA-SHA256"
};
export { ALGORITHMS_IDS };

// Generic AlgorithmIdentifier (RFC 3280 s4.1.1.2): an algorithm OID with
// optional, algorithm-dependent parameters kept here as raw DER.
var AlgorithmIdentifier = asn1.define("AlgorithmIdentifier", function () {
  this.seq().obj(
    this.key("algorithm").objid(ALGORITHMS_IDS),
    this.key("parameters").optional().any()
  );
});
export { AlgorithmIdentifier };

// X.509 Certificate: the signed TBSCertificate, the CA's signatureAlgorithm and
// the signature bit string over the DER of tbsCertificate.
var Certificate = asn1.define("Certificate", function () {
  this.seq().obj(
    this.key("tbsCertificate").use(TBSCertificate),
    this.key("signatureAlgorithm").use(AlgorithmIdentifier),
    this.key("signature").bitstr()
  );
});
export { Certificate };

// TBSCertificate: the "to be signed" body carrying identity and key material.
var TBSCertificate = asn1.define("TBSCertificate", function () {
  this.seq().obj(
    this.key("version").def("v1").explicit(0).use(Version),
    this.key("serialNumber").use(CertificateSerialNumber),
    this.key("signature").use(AlgorithmIdentifier),
    this.key("issuer").use(Name),
    this.key("validity").use(Validity),
    this.key("subject").use(Name),
    this.key("subjectPublicKeyInfo").use(SubjectPublicKeyInfo),

    // Limitation: RFC 3280 s4.1.2.8 allows unique identifiers only for
    // v2/v3 certificates, but the version field is not cross-checked here —
    // a malformed v1 certificate carrying these fields still parses.
    this.key("issuerUniqueID").optional().implicit(1).use(UniqueIdentifier),
    this.key("subjectUniqueID").optional().implicit(2).use(UniqueIdentifier),

    // Limitation: extensions are only valid for v3 (RFC 3280 s4.1.2.9);
    // the version/extensions consistency is likewise not enforced. Lenient
    // parsing is deliberate — real-world CA output is not always strict.
    this.key("extensions").optional().explicit(3).use(Extensions)
  );
});
export { TBSCertificate };

// Certificate version, encoded as INTEGER 0/1/2 for v1/v2/v3.
var Version = asn1.define("Version", function () {
  this.int({
    0: "v1",
    1: "v2",
    2: "v3"
  });
});
export { Version };

// Certificate serial number (an arbitrarily large INTEGER).
var CertificateSerialNumber = asn1.define(
  "CertificateSerialNumber",
  function () {
    this.int();
  }
);
export { CertificateSerialNumber };

// Validity window of a certificate (notBefore .. notAfter).
var Validity = asn1.define("Validity", function () {
  this.seq().obj(
    this.key("notBefore").use(Time),
    this.key("notAfter").use(Time)
  );
});
export { Validity };

// X.509 Time CHOICE: UTCTime (2-digit year) or GeneralizedTime (4-digit year).
var Time = asn1.define("Time", function () {
  this.choice({
    utcTime: this.utctime(),
    genTime: this.gentime()
  });
});
export { Time };

// Optional issuer/subject unique identifiers (v2/v3), a bit string.
var UniqueIdentifier = asn1.define("UniqueIdentifier", function () {
  this.bitstr();
});
export { UniqueIdentifier };

// Fallback parser that keeps public-key algorithm parameters as raw ANY DER.
var AnyAlgorithmParams = asn1.define("AlgorithmParams", function () {
  this.any();
});

// Registry of per-algorithm public-key parameter parsers, keyed by algorithm
// name; "any" is the default. Populated at runtime via injectPubAlgo() so the
// DSTU 4145 curve parameters can be decoded without a hard dependency here.
var PUBKEY_PARAMS = {
  any: AnyAlgorithmParams
};
// AlgorithmIdentifier for a subject public key: unlike the generic
// AlgorithmIdentifier, the parameters are parsed with the structure registered
// in PUBKEY_PARAMS for this algorithm (e.g. DSTU 4145 domain parameters).
var PubkeyAlgorithmIdentifier = asn1.define(
  "PubkeyAlgorithmIdentifier",
  function () {
    this.seq().obj(
      this.key("algorithm").objid(ALGORITHMS_IDS),
      this.key("parameters").use(function (obj) {
        return PUBKEY_PARAMS[obj.algorithm] || PUBKEY_PARAMS.any;
      })
    );
  }
);

// SubjectPublicKeyInfo: the public key algorithm/parameters and the key itself.
var SubjectPublicKeyInfo = asn1.define("SubjectPublicKeyInfo", function () {
  this.seq().obj(
    this.key("algorithm").use(PubkeyAlgorithmIdentifier),
    this.key("subjectPublicKey").bitstr()
  );
});
export { SubjectPublicKeyInfo };

// SEQUENCE OF Extension, the v3 extensions block.
var Extensions = asn1.define("Extensions", function () {
  this.seqof(Extension);
});
export { Extensions };

// OID -> name map for the certificate extensions recognised by this library
// (mostly the PKIX 1.3.6.1.5.5.7.1.* private extensions and the standard
// 2.5.29.* certificate/CRL extensions).
var extnIdMap = {
  "1 3 6 1 5 5 7 1 1": "authorityInfoAccess",
  "1 3 6 1 5 5 7 1 2": "biometricInfo",
  "1 3 6 1 5 5 7 1 3": "qcStatements",
  "1 3 6 1 5 5 7 1 4": "ac-auditEntity",
  "1 3 6 1 5 5 7 1 5": "ac-targeting",
  "1 3 6 1 5 5 7 1 6": "aaControls",
  "1 3 6 1 5 5 7 1 7": "sbgp-ipAddrBlock",
  "1 3 6 1 5 5 7 1 8": "sbgp-autonomousSysNum",
  "1 3 6 1 5 5 7 1 9": "sbgp-routerIdentifier",
  "1 3 6 1 5 5 7 1 10": "ac-proxying",
  "1 3 6 1 5 5 7 1 11": "subjectInfoAccess",
  "1 3 6 1 5 5 7 1 14": "proxyCertInfo",
  "2 5 29 9": "subjectDirectoryAttributes",
  "2 5 29 14": "subjectKeyIdentifier",
  "2 5 29 15": "keyUsage",
  "2 5 29 16": "privateKeyUsagePeriod",
  "2 5 29 17": "subjectAltName",
  "2 5 29 18": "issuerAltName",
  "2 5 29 19": "basicConstraints",
  "2 5 29 20": "crlNumber",
  "2 5 29 21": "CRLReason",
  "2 5 29 24": "invalidityDate",
  "2 5 29 27": "deltaCRL",
  "2 5 29 28": "issuingDistributionPoint",
  "2 5 29 29": "certificateIssuer",
  "2 5 29 30": "nameConstraints",
  "2 5 29 31": "crlDistributionPoints",
  "2 5 29 32": "certificatePolicies",
  "2 5 29 32 0": "anyPolicy",
  "2 5 29 33": "policyMappings",
  "2 5 29 35": "authorityKeyIdentifier",
  "2 5 29 36": "policyConstraints",
  "2 5 29 37": "extendedKeyUsage",
  "2 5 29 46": "freshestCRL",
  "2 5 29 54": "inhibitAnyPolicy",
  "2 5 29 55": "targetInformation",
  "2 5 29 56": "noRevAvail",
  "1 3 6 1 5 5 7 48 1 2": "OCSPNonce"
};

// A single certificate extension: its OID, the critical flag (default false),
// and the DER-encoded extnValue (left as an OCTET STRING for later parsing).
var Extension = asn1.define("Extension", function () {
  this.seq().obj(
    this.key("extnID").objid(extnIdMap),
    this.key("critical").bool().def(false),
    this.key("extnValue").octstr()
  );
});
export { Extension };

/**

  Name ::= CHOICE { -- only one possibility for now --
      rdnSequence  RDNSequence }

*/
var Name = asn1.define("Name", function () {
  this.choice({
    rdn: this.use(RDNSequence)
  });
});
export { Name };

// A distinguished name as an ordered sequence of RDNs (most-significant first).
var RDNSequence = asn1.define("RDNSequence", function () {
  this.seqof(RelativeDistinguishedName);
});
export { RDNSequence };

// One RDN: a SET of type/value pairs (usually one) sharing the same name level.
var RelativeDistinguishedName = asn1.define(
  "RelativeDistinguishedName",
  function () {
    this.setof(AttributeTypeAndValue);
  }
);
export { RelativeDistinguishedName };

// A naming attribute: its type OID and the (untyped) value DER.
var AttributeTypeAndValue = asn1.define("AttributeTypeAndValue", function () {
  this.seq().obj(
    this.key("type").use(AttributeType),
    this.key("value").use(AttributeValue)
  );
});
export { AttributeTypeAndValue };

// OID -> name map covering both PKCS#9 signed-attribute OIDs (1.2.840.113549.1.9.*)
// and the X.520 directory attribute types (2.5.4.*) that appear in names.
var AttributeObjId = {
  "1 2 840 113549 1 9 3": "contentType",
  "1 2 840 113549 1 9 4": "messageDigest",
  "1 2 840 113549 1 9 5": "signingTime",
  "1 2 840 113549 1 9 16 2 47": "signingCertificateV2",
  "1 2 840 113549 1 9 16 2 20": "contentTimeStamp",
  "1 2 840 113549 1 9 16 2 14": "timeStampToken",
  "1 2 840 113549 1 9 16 2 21": "certificateRefs",
  "1 2 840 113549 1 9 16 2 22": "revocationRefs",
  "1 2 840 113549 1 9 16 2 23": "certificateValues",
  "1 2 840 113549 1 9 16 2 24": "revocationValues",
  "2 5 4 3": "commonName",
  "2 5 4 4": "surname",
  "2 5 4 5": "serialNumber",
  "2 5 4 6": "countryName",
  "2 5 4 7": "localityName",
  "2 5 4 8": "stateOrProvinceName",
  "2 5 4 9": "streetAddress",
  "2 5 4 10": "organizationName",
  "2 5 4 11": "organizationalUnitName",
  "2 5 4 12": "title",
  "2 5 4 13": "description",
  "2 5 4 14": "searchGuide",
  "2 5 4 15": "businessCategory",
  "2 5 4 16": "postalAddress",
  "2 5 4 17": "postalCode",
  "2 5 4 18": "postOfficeBox",
  "2 5 4 19": "physicalDeliveryOfficeName",
  "2 5 4 20": "telephoneNumber",
  "2 5 4 21": "telexNumber",
  "2 5 4 22": "teletexTerminalIdentifier",
  "2 5 4 23": "facsimileTelephoneNumber",
  "2 5 4 24": "x121Address",
  "2 5 4 25": "internationaliSDNNumber",
  "2 5 4 26": "registeredAddress",
  "2 5 4 27": "destinationIndicator",
  "2 5 4 28": "preferredDeliveryMethod",
  "2 5 4 29": "presentationAddress",
  "2 5 4 30": "supportedApplicationContext",
  "2 5 4 31": "member",
  "2 5 4 32": "owner",
  "2 5 4 33": "roleOccupant",
  "2 5 4 34": "seeAlso",
  "2 5 4 35": "userPassword",
  "2 5 4 36": "userCertificate",
  "2 5 4 37": "cACertificate",
  "2 5 4 38": "authorityRevocationList",
  "2 5 4 39": "certificateRevocationList",
  "2 5 4 40": "crossCertificatePair",
  "2 5 4 41": "name",
  "2 5 4 42": "givenName",
  "2 5 4 43": "initials",
  "2 5 4 44": "generationQualifier",
  "2 5 4 45": "x500UniqueIdentifier",
  "2 5 4 46": "dnQualifier",
  "2 5 4 47": "enhancedSearchGuide",
  "2 5 4 48": "protocolInformation",
  "2 5 4 49": "distinguishedName",
  "2 5 4 50": "uniqueMember",
  "2 5 4 51": "houseIdentifier",
  "2 5 4 52": "supportedAlgorithms",
  "2 5 4 53": "deltaRevocationList",
  "2 5 4 54": "dmdName",
  "2 5 4 65": "pseudonym",
  "2 5 4 72": "role",
  "2 5 4 97": "organizationIdentifier"
};
// Attribute type OID resolved against AttributeObjId.
var AttributeType = asn1.define("AttributeType", function () {
  this.objid(AttributeObjId);
});
export { AttributeType };

// Attribute value kept as raw ANY DER (its type depends on the attribute).
var AttributeValue = asn1.define("AttributeValue", function () {
  this.any();
});
export { AttributeValue };

// Extended key usage purpose OIDs recognised here (timestamping, OCSP signing).
var KeyPurposeIdMap = {
  "1 3 6 1 5 5 7 3 8": "timeStamping",
  "1 3 6 1 5 5 7 3 9": "ocspSigning"
};
var KeyPurposeId = asn1.define("KeyPurposeId", function () {
  this.objid(KeyPurposeIdMap);
});

// extendedKeyUsage extension value: SEQUENCE OF KeyPurposeId.
var ExtKeyUsageSyntax = asn1.define("ExtKeyUsageSyntax", function () {
  this.seqof(KeyPurposeId);
});
export { ExtKeyUsageSyntax };

// basicConstraints extension value: whether the subject is a CA and the maximum
// path length of subordinate CAs below it.
var BasicConstraints = asn1.define("BasicConstraints", function () {
  this.seq().obj(
    this.key("cA").bool().def(false),
    this.key("pathLenConstraint").int().optional()
  );
});
export { BasicConstraints };

/**
 * Register a parser for a public-key algorithm's parameters, so that
 * SubjectPublicKeyInfo can decode them (e.g. DSTU 4145 domain parameters)
 * instead of falling back to raw ANY DER.
 *
 * @param {string} algo algorithm name (as resolved from ALGORITHMS_IDS)
 * @param {object} paramSpec asn1.js structure used to parse the parameters
 */
export function injectPubAlgo(algo, paramSpec) {
  PUBKEY_PARAMS[algo] = paramSpec;
}
