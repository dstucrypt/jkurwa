var asn1 = require('asn1.js'),
    rfc3280 = require('./rfc3280');

/**
  http://tools.ietf.org/html/rfc2315#section-14

  pkcs-7 OBJECT IDENTIFIER ::=
     { iso(1) member-body(2) US(840) rsadsi(113549)
         pkcs(1) 7 }

  data OBJECT IDENTIFIER ::= { pkcs-7 1 }
  signedData OBJECT IDENTIFIER ::= { pkcs-7 2 }
  envelopedData OBJECT IDENTIFIER ::= { pkcs-7 3 }
  signedAndEnvelopedData OBJECT IDENTIFIER ::=
     { pkcs-7 4 }
  digestedData OBJECT IDENTIFIER ::= { pkcs-7 5 }
  encryptedData OBJECT IDENTIFIER ::= { pkcs-7 6 }
*/
var PKCS7_CONTENT_TYPES = {
    "1 2 840 113549 1 7 1": "data",
    "1 2 840 113549 1 7 2": "signedData",
    "1 2 840 113549 1 7 3": "envelopedData",
    "1 2 840 113549 1 7 4": "signedAndEnvelopedData",
    "1 2 840 113549 1 7 5": "digestData",
    "1 2 840 113549 1 7 6": "encryptedData",
};

/**
  http://tools.ietf.org/html/rfc2315#section-7

  ContentInfo ::= SEQUENCE {
     contentType ContentType,
     content
       [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
*/
var ContentInfo = asn1.define('ContentInfo', function() {
    this.seq().obj(
        this.key('contentType').objid(PKCS7_CONTENT_TYPES),
        this.key('content').optional().explicit(0).choice({
            buffer: this.octstr(),
            raw: this.any()
        })
    );
});

/**
  DSTU GOST 28147:2009

  TODO missing
*/
var GOST28147Parameters = asn1.define('GOST28147Parameters', function() {
    this.seq().obj(
        this.key('iv').octstr(),
        this.key('dke').octstr()
    )
});

/**
  http://tools.ietf.org/html/rfc2315#section-6.2

  ContentEncryptionAlgorithmIdentifier ::=
    AlgorithmIdentifier

  http://tools.ietf.org/html/rfc3280#section-4.1.1.2

  AlgorithmIdentifier  ::=  SEQUENCE  {
    algorithm               OBJECT IDENTIFIER,
    parameters              ANY DEFINED BY algorithm OPTIONAL  }


  DSTU GOST 28147:2009
  TODO missing

*/
var ContentEncryptionAlgorithmIdentifier = asn1.define('ContentEncryptionAlgorithmIdentifier', function() {
    this.seq().obj(
        this.key('algorithm').objid(rfc3280.ALGORITHMS_IDS),
        this.key('parameters').choice({
            null_: this.null_(),
            params: this.use(GOST28147Parameters)
        })
    )
});

module.exports.ContentEncryptionAlgorithmIdentifier = ContentEncryptionAlgorithmIdentifier;

var DigestAlgorithmIdentifier = asn1.define('DigestAlgorithmIdentifier', function() {
    this.use(rfc3280.AlgorithmIdentifier);
});

var DigestAlgorithmIdentifiers = asn1.define('DigestAlgorithmIdentifiers', function() {
    this.setof(DigestAlgorithmIdentifier);
})

var KeyEncryptionAlgorithmIdentifier = asn1.define('KeyEncryptionAlgorithmIdentifier', function() {
    this.use(rfc3280.AlgorithmIdentifier);
})


/**
  http://tools.ietf.org/html/rfc2315#section-6.7

  IssuerAndSerialNumber ::= SEQUENCE {
    issuer Name,
    serialNumber CertificateSerialNumber }

*/
var IssuerAndSerialNumber = asn1.define('IssuerAndSerialNumber', function() {
    this.seq().obj(
        this.key('issuer').use(rfc3280.Name),
        this.key('serialNumber').use(rfc3280.CertificateSerialNumber)
    );
});

/**
  Attribute: A type that contains an attribute type (specified by
  object identifier) and one or more attribute values. This type is
  defined in X.501.

  Attribute ::= SEQUENCE {
  type AttributeType ( { SupportedAttributes } ),
  values SET SIZE (1 .. MAX) OF AttributeValue ( { SupportedAttributes}{@type})}

*/
var Attribute = asn1.define('Attribute', function() {
    this.seq().obj(
        this.key("type").use(rfc3280.AttributeType),
        this.key('values').setof(rfc3280.AttributeValue)
    );
});

var Attributes = asn1.define('Attributes', function() {
    this.seqof(Attribute);
});

var DigestEncryptionAlgorithmIdentifier = asn1.define('DigestEncryptionAlgorithmIdentifier', function() {
    this.use(rfc3280.AlgorithmIdentifier)
});

/**

  http://tools.ietf.org/html/rfc2315#section-9.2

  SignerInfo ::= SEQUENCE {
    version Version,
    issuerAndSerialNumber IssuerAndSerialNumber,
    digestAlgorithm DigestAlgorithmIdentifier,
    authenticatedAttributes
      [0] IMPLICIT Attributes OPTIONAL,
    digestEncryptionAlgorithm
      DigestEncryptionAlgorithmIdentifier,
    encryptedDigest EncryptedDigest,
    unauthenticatedAttributes
      [1] IMPLICIT Attributes OPTIONAL }

*/
var SignerInfo = asn1.define('SignerInfo', function() {
    this.seq().obj(
        this.key('version').int(),
        this.key('issuerAndSerialNumber').use(IssuerAndSerialNumber),
        this.key('digestAlgorithm').use(DigestAlgorithmIdentifier),
        this.key('authenticatedAttributes').optional().implicit(0).seqof(
            Attribute
        ),
        this.key('digestEncryptionAlgorithm').use(DigestEncryptionAlgorithmIdentifier),
        this.key('encryptedDigest').octstr(),
        this.key('unauthenticatedAttributes').optional().implicit(1).seqof(
            Attribute
        )
    );
});

var SignerInfos = asn1.define('SignerInfos', function() {
    this.setof(SignerInfo);
});

/**
  http://tools.ietf.org/html/rfc2315#section-9.1

  SignedData ::= SEQUENCE {
    version Version,
    digestAlgorithms DigestAlgorithmIdentifiers,
    contentInfo ContentInfo,
    certificates
       [0] IMPLICIT ExtendedCertificatesAndCertificates
         OPTIONAL,
    crls
      [1] IMPLICIT CertificateRevocationLists OPTIONAL,
    signerInfos SignerInfos }
*/
var SignedData = asn1.define('SignedData', function() {
    this.seq().obj(
        this.key('version').int(),
        this.key('digestAlgorithms').use(DigestAlgorithmIdentifiers),
        this.key('contentInfo').use(ContentInfo),
        this.key('certificate').optional().explicit(0).use(rfc3280.Certificate),
        this.key('crls').optional().implicit(1).any(), // NOT PARSED
        this.key('signerInfos').use(SignerInfos)
    );
});


var RecipientKeyIdentifier = asn1.define('RecipientKeyIdentifier', function() {
    this.key('subjectKeyIdentifier').octstr(),
    this.key('date').use(rfc3280.Time),
    this.key('other').optional().any()
});

var KeyAgreeRecipientIdentifier = asn1.define('KeyAgreeRecipientIdentifier', function() {
    this.choice({
        issuerAndSerialNumber: this.use(IssuerAndSerialNumber),
        rKeyId: this.implicit(0).use(RecipientKeyIdentifier)
    });
});

var RecipientEncryptedKey = asn1.define('RecipientEncryptedKey', function() {
    this.seq().obj(
        this.key('rid').use(KeyAgreeRecipientIdentifier),
        this.key('encryptedKey').octstr()
    )
});

/**
  http://tools.ietf.org/html/rfc2315#section-6.7

  IssuerAndSerialNumber ::= SEQUENCE {
    issuer Name,
    serialNumber CertificateSerialNumber }
*/
var OriginatorInfo = asn1.define('OriginatorInfo', function() {
    this.implicit(0).seq().obj( // BUG!
        this.key('certificates').use(IssuerAndSerialNumber)
    );
});

/**
  http://tools.ietf.org/html/rfc2315#section-10.2

  RecipientInfo ::= SEQUENCE {
    version Version,
    issuerAndSerialNumber IssuerAndSerialNumber,
    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    encryptedKey EncryptedKey }

  EncryptedKey ::= OCTET STRING

*/
var KeyAgreeRecipientInfo = asn1.define('KeyAgreeRecipientInfo', function() {
    this.implicit(1).seq().obj( // BUG!
        this.key('version').int(),
        this.key('originator').optional().implicit(0).use(OriginatorInfo),
        this.key('ukm').explicit(1).octstr(),
        this.key('keyEncryptionAlgorithm').use(KeyEncryptionAlgorithmIdentifier),
        this.key('recipientEncryptedKeys').seqof(RecipientEncryptedKey)
    );
});

var RecipientInfo = asn1.define('RecipientInfo', function() {
    this.choice({
        kari: this.implicit(1).use(KeyAgreeRecipientInfo)
    })
});

/**
  http://tools.ietf.org/html/rfc2315#section-10.1

  EncryptedContentInfo ::= SEQUENCE {
    contentType ContentType,
    contentEncryptionAlgorithm
      ContentEncryptionAlgorithmIdentifier,
    encryptedContent
      [0] IMPLICIT EncryptedContent OPTIONAL }

  EncryptedContent ::= OCTET STRING

*/
var EncryptedContentInfo = asn1.define('EncryptedContentInfo', function() {
    this.seq().obj(
        this.key('contentType').objid(PKCS7_CONTENT_TYPES),
        this.key('contentEncryptionAlgorithm').use(ContentEncryptionAlgorithmIdentifier),
        this.key('encryptedContent').optional().implicit(0).octstr()
    );
});

/**
  http://tools.ietf.org/html/rfc2315#section-10.1

  EnvelopedData ::= SEQUENCE {
    version Version,
    recipientInfos RecipientInfos,
    encryptedContentInfo EncryptedContentInfo }
*/
var EnvelopedData = asn1.define('EnvelopedData', function() {
    this.seq().obj(
        this.key('version').int(),
        this.key('recipientInfos').setof(RecipientInfo),
        this.key('encryptedContentInfo').use(EncryptedContentInfo)
    );
});

ContentInfo.contentModel = {
    signedData: SignedData,
    envelopedData: EnvelopedData,
};


module.exports.ContentInfo = ContentInfo;

var WrapAlgo = asn1.define('WrapAlgo', function() {
    this.seq().obj(
        this.key('algorithm').objid(rfc3280.ALGORITHMS_IDS),
        this.key("parameters").null_()
    )
})

var SharedInfo = asn1.define('SharedInfo', function() {
    this.seq().obj(
        this.key("keyInfo").use(WrapAlgo),
        this.key("entityInfo").optional().explicit(0).octstr(),
        this.key("suppPubInfo").explicit(2).octstr()
    );
});

module.exports.SharedInfo = SharedInfo;
