var asn1 = require('asn1.js');

var CRLReason = asn1.define('CRLReason', function() {
  this.enum({
    0: 'unspecified',
    1: 'keyCompromise',
    2: 'CACompromise',
    3: 'affiliationChanged',
    4: 'superseded',
    5: 'cessationOfOperation',
    6: 'certificateHold',
    8: 'removeFromCRL',
    9: 'privilegeWithdrawn',
    10: 'AACompromise'
  });
});
exports.CRLReason = CRLReason;

var ALGORITHMS_IDS = {
    "1 2 804 2 1 1 1 1 2 1": "Gost34311",
    '1 2 804 2 1 1 1 1 1 1 3': "Gost28147-cfb",
    '1 2 804 2 1 1 1 1 3 4': 'dhSinglePass-cofactorDH-gost34311kdf',
    "1 2 804 2 1 1 1 1 1 1 5": "Gost28147-cfb-wrap",
    '1 2 804 2 1 1 1 1 1 2': "Gost34311-hmac",
    '1 2 804 2 1 1 1 1 3 1 1': "Dstu4145le",
    '1 2 840 10045 2 1': 'ECDSA',
    '1 2 840 10045 4 3 2': 'ECDSA-SHA256',
};
exports.ALGORITHMS_IDS = ALGORITHMS_IDS;

var AlgorithmIdentifier = asn1.define('AlgorithmIdentifier', function() {
  this.seq().obj(
    this.key('algorithm').objid(ALGORITHMS_IDS),
    this.key('parameters').optional().any()
  );
});
exports.AlgorithmIdentifier = AlgorithmIdentifier;

var Certificate = asn1.define('Certificate', function() {
  this.seq().obj(
    this.key('tbsCertificate').use(TBSCertificate),
    this.key('signatureAlgorithm').use(AlgorithmIdentifier),
    this.key('signature').bitstr()
  );
});
exports.Certificate = Certificate;

var TBSCertificate = asn1.define('TBSCertificate', function() {
  this.seq().obj(
    this.key('version').def('v1').explicit(0).use(Version),
    this.key('serialNumber').use(CertificateSerialNumber),
    this.key('signature').use(AlgorithmIdentifier),
    this.key('issuer').use(Name),
    this.key('validity').use(Validity),
    this.key('subject').use(Name),
    this.key('subjectPublicKeyInfo').use(SubjectPublicKeyInfo),

    // TODO(indutny): validate that version is v2 or v3
    this.key('issuerUniqueID').optional().implicit(1).use(UniqueIdentifier),
    this.key('subjectUniqueID').optional().implicit(2).use(UniqueIdentifier),

    // TODO(indutny): validate that version is v3
    this.key('extensions').optional().explicit(3).use(Extensions)
  );
});
exports.TBSCertificate = TBSCertificate;

var Version = asn1.define('Version', function() {
  this.int({
    0: 'v1',
    1: 'v2',
    2: 'v3'
  });
});
exports.Version = Version;

var CertificateSerialNumber = asn1.define('CertificateSerialNumber',
                                          function() {
  this.int();
});
exports.CertificateSerialNumber = CertificateSerialNumber;

var Validity = asn1.define('Validity', function() {
  this.seq().obj(
    this.key('notBefore').use(Time),
    this.key('notAfter').use(Time)
  );
});
exports.Validity = Validity;

var Time = asn1.define('Time', function() {
  this.choice({
    utcTime: this.utctime(),
    genTime: this.gentime()
  });
});
exports.Time = Time;

var UniqueIdentifier = asn1.define('UniqueIdentifier', function() {
  this.bitstr();
});
exports.UniqueIdentifier = UniqueIdentifier;

var AnyAlgorithmParams = asn1.define('AlgorithmParams', function() {
  this.any();
});

var PUBKEY_PARAMS = {
  'any': AnyAlgorithmParams,
};
var PubkeyAlgorithmIdentifier = asn1.define('PubkeyAlgorithmIdentifier', function() {
  this.seq().obj(
    this.key('algorithm').objid(ALGORITHMS_IDS),
    this.key('parameters').use(function(obj) {
      return PUBKEY_PARAMS[obj.algorithm] || PUBKEY_PARAMS.any;
    })
  );
});


var SubjectPublicKeyInfo = asn1.define('SubjectPublicKeyInfo', function() {
  this.seq().obj(
    this.key('algorithm').use(PubkeyAlgorithmIdentifier),
    this.key('subjectPublicKey').bitstr()
  );
});
exports.SubjectPublicKeyInfo = SubjectPublicKeyInfo;

var Extensions = asn1.define('Extensions', function() {
  this.seqof(Extension)
});
exports.Extensions = Extensions;

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
'2 5 29 9': 'subjectDirectoryAttributes',
'2 5 29 14': 'subjectKeyIdentifier',
'2 5 29 15': 'keyUsage',
'2 5 29 16': 'privateKeyUsagePeriod',
'2 5 29 17': 'subjectAltName',
'2 5 29 18': 'issuerAltName',
'2 5 29 19': 'basicConstraints',
'2 5 29 20': 'crlNumber',
'2 5 29 21': 'CRLReason',
'2 5 29 24': 'invalidityDate',
'2 5 29 27': 'deltaCRL',
'2 5 29 28': 'issuingDistributionPoint',
'2 5 29 29': 'certificateIssuer',
'2 5 29 30': 'nameConstraints',
'2 5 29 31': 'crlDistributionPoints',
'2 5 29 32': 'certificatePolicies',
'2 5 29 32 0': 'anyPolicy',
'2 5 29 33': 'policyMappings',
'2 5 29 35': 'authorityKeyIdentifier',
'2 5 29 36': 'policyConstraints',
'2 5 29 37': 'extendedKeyUsage',
'2 5 29 46': 'freshestCRL',
'2 5 29 54': 'inhibitAnyPolicy',
'2 5 29 55': 'targetInformation',
'2 5 29 56': 'noRevAvail',
'1 3 6 1 5 5 7 48 1 2': 'OCSPNonce',
}

var Extension = asn1.define('Extension', function() {
  this.seq().obj(
    this.key('extnID').objid(extnIdMap),
    this.key('critical').bool().def(false),
    this.key('extnValue').octstr()
  );
});
exports.Extension = Extension;

/**

  Name ::= CHOICE { -- only one possibility for now --
      rdnSequence  RDNSequence }

*/
var Name = asn1.define('Name', function() {
  this.choice({
    rdn: this.use(RDNSequence)
  });
});
exports.Name = Name;

var RDNSequence = asn1.define('RDNSequence', function() {
  this.seqof(RelativeDistinguishedName);
});
exports.RDNSequence = RDNSequence;

var RelativeDistinguishedName = asn1.define('RelativeDistinguishedName',
                                            function() {
  this.setof(AttributeTypeAndValue);
});
exports.RelativeDistinguishedName = RelativeDistinguishedName;

var AttributeTypeAndValue = asn1.define('AttributeTypeAndValue', function() {
  this.seq().obj(
    this.key('type').use(AttributeType),
    this.key('value').use(AttributeValue)
  );
});
exports.AttributeTypeAndValue = AttributeTypeAndValue;

var AttributeObjId = {
    '1 2 840 113549 1 9 3': 'contentType',
    '1 2 840 113549 1 9 4': 'messageDigest',
    '1 2 840 113549 1 9 5': 'signingTime',
    '1 2 840 113549 1 9 16 2 47': 'signingCertificateV2',
    '1 2 840 113549 1 9 16 2 20': 'contentTimeStamp',
    '2 5 4 3': 'commonName',
    '2 5 4 4': 'surname',
    '2 5 4 5': 'serialNumber',
    '2 5 4 6': 'countryName',
    '2 5 4 7': 'localityName',
    '2 5 4 8': 'stateOrProvinceName',
    '2 5 4 9': 'streetAddress',
    '2 5 4 10': 'organizationName',
    '2 5 4 11': 'organizationalUnitName',
    '2 5 4 12': 'title',
    '2 5 4 13': 'description',
    '2 5 4 14': 'searchGuide',
    '2 5 4 15': 'businessCategory',
    '2 5 4 16': 'postalAddress',
    '2 5 4 17': 'postalCode',
    '2 5 4 18': 'postOfficeBox',
    '2 5 4 19': 'physicalDeliveryOfficeName',
    '2 5 4 20': 'telephoneNumber',
    '2 5 4 21': 'telexNumber',
    '2 5 4 22': 'teletexTerminalIdentifier',
    '2 5 4 23': 'facsimileTelephoneNumber',
    '2 5 4 24': 'x121Address',
    '2 5 4 25': 'internationaliSDNNumber',
    '2 5 4 26': 'registeredAddress',
    '2 5 4 27': 'destinationIndicator',
    '2 5 4 28': 'preferredDeliveryMethod',
    '2 5 4 29': 'presentationAddress',
    '2 5 4 30': 'supportedApplicationContext',
    '2 5 4 31': 'member',
    '2 5 4 32': 'owner',
    '2 5 4 33': 'roleOccupant',
    '2 5 4 34': 'seeAlso',
    '2 5 4 35': 'userPassword',
    '2 5 4 36': 'userCertificate',
    '2 5 4 37': 'cACertificate',
    '2 5 4 38': 'authorityRevocationList',
    '2 5 4 39': 'certificateRevocationList',
    '2 5 4 40': 'crossCertificatePair',
    '2 5 4 41': 'name',
    '2 5 4 42': 'givenName',
    '2 5 4 43': 'initials',
    '2 5 4 44': 'generationQualifier',
    '2 5 4 45': 'x500UniqueIdentifier',
    '2 5 4 46': 'dnQualifier',
    '2 5 4 47': 'enhancedSearchGuide',
    '2 5 4 48': 'protocolInformation',
    '2 5 4 49': 'distinguishedName',
    '2 5 4 50': 'uniqueMember',
    '2 5 4 51': 'houseIdentifier',
    '2 5 4 52': 'supportedAlgorithms',
    '2 5 4 53': 'deltaRevocationList',
    '2 5 4 54': 'dmdName',
    '2 5 4 65': 'pseudonym',
    '2 5 4 72': 'role',
    '2 5 4 97': 'organizationIdentifier',
}
var AttributeType = asn1.define('AttributeType', function() {
  this.objid(AttributeObjId)
});
exports.AttributeType = AttributeType;

var AttributeValue = asn1.define('AttributeValue', function() {
  this.any();
});
exports.AttributeValue = AttributeValue;

exports.injectPubAlgo = function(algo, paramSpec) {
    PUBKEY_PARAMS[algo] = paramSpec;
};
