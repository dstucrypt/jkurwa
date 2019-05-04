var asn1 = require('asn1.js'),
    rfc3280 = require('./rfc3280'),
    Buffer = require('buffer').Buffer;

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
    "1 2 840 113549 1 9 16 1 4": "tstInfo",
};

var ContentType = asn1.define('ContentType', function() {
    this.objid(PKCS7_CONTENT_TYPES);
});
module.exports.ContentType = ContentType;

/**
  http://tools.ietf.org/html/rfc2315#section-7

  ContentInfo ::= SEQUENCE {
     contentType ContentType,
     content
       [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
*/
var ContentInfo = asn1.define('ContentInfo', function() {
    this.seq().obj(
        this.key('contentType').use(ContentType),
        this.key('content').optional().explicit(0).use(function(obj) {
            var model = ContentInfo.contentModel[obj.contentType];
            if(model === undefined) {
                throw new Error("Can't parse " + obj.contentType + " in PKCS#7");
            }
            return model;
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
    );
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
    );
});

module.exports.ContentEncryptionAlgorithmIdentifier = ContentEncryptionAlgorithmIdentifier;

var DigestAlgorithmIdentifier = asn1.define('DigestAlgorithmIdentifier', function() {
    this.use(rfc3280.AlgorithmIdentifier);
});

var DigestAlgorithmIdentifiers = asn1.define('DigestAlgorithmIdentifiers', function() {
    this.setof(DigestAlgorithmIdentifier);
});

var KeyEncryptionAlgorithmIdentifier = asn1.define('KeyEncryptionAlgorithmIdentifier', function() {
    this.seq().obj(
        this.key('algorithm').objid(rfc3280.ALGORITHMS_IDS),
        this.key('parameters').use(WrapAlgo)
    );
});


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
    this.setof(Attribute);
});
module.exports.Attributes = Attributes;

var DigestEncryptionAlgorithmIdentifier = asn1.define('DigestEncryptionAlgorithmIdentifier', function() {
    this.use(rfc3280.AlgorithmIdentifier);
});


var SubjectKeyIdentifier = asn1.define('SubjectKeyIdentifier', function() {
    this.octstr();
});

var SignerIdentifier = asn1.define('SignerIdentifier', function() {
    this.choice({
        issuerAndSerialNumber: this.use(IssuerAndSerialNumber),
        subjectKeyIdentifier: this.explicit(0).use(SubjectKeyIdentifier)
    });
});

/**

  http://www.ietf.org/rfc/rfc3852.txt

  SignerInfo ::= SEQUENCE {
    version Version,
    sid SignerIdentifier,
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
        this.key('sid').use(SignerIdentifier),
        this.key('digestAlgorithm').use(DigestAlgorithmIdentifier),
        this.key('authenticatedAttributes').optional().implicit(0).use(Attributes),
        this.key('digestEncryptionAlgorithm').use(DigestEncryptionAlgorithmIdentifier),
        this.key('encryptedDigest').octstr(),
        this.key('unauthenticatedAttributes').optional().implicit(1).use(Attributes)
    );
});

var SignerInfos = asn1.define('SignerInfos', function() {
    this.setof(SignerInfo);
});

var Certificates = asn1.define('Certificates', function() {
    this.seqof(rfc3280.Certificate);
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
        this.key('certificate').optional().implicit(0).use(Certificates),
        this.key('crls').optional().implicit(1).set(), // NOT PARSED
        this.key('signerInfos').use(SignerInfos)
    );
});


var RecipientKeyIdentifier = asn1.define('RecipientKeyIdentifier', function() {
    this.seq().obj(
        this.key('subjectKeyIdentifier').octstr(),
        this.key('date').use(rfc3280.Time).optional(),
        this.key('other').optional().any()
    );
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
    );
});

/**
  http://tools.ietf.org/html/rfc2315#section-6.7

  IssuerAndSerialNumber ::= SEQUENCE {
    issuer Name,
    serialNumber CertificateSerialNumber }
*/
var OriginatorInfo = asn1.define('OriginatorInfo', function() {
    this.seq().obj(
        this.key('certificates').use(IssuerAndSerialNumber)
    );
});

var OriginatorPublicKey = asn1.define('OriginatorPublicKey', function () {
    this.seq().obj(
        this.key('algorithm').use(rfc3280.AlgorithmIdentifier),
        this.key('publicKey').bitstr()
    );
});

var OriginatorIdentifierOrKey = asn1.define('OriginatorIdentifierOrKey', function() {
    this.seq().choice({
        issuerAndSerialNumber: this.use(IssuerAndSerialNumber),
        subjectKeyIdentifier: this.implicit(0).use(SubjectKeyIdentifier),
        originatorKey: this.implicit(1).use(OriginatorPublicKey)
    });
});

/**
  https://tools.ietf.org/html/rfc5652#section-6.2

  RecipientInfo ::= SEQUENCE {
    version Version,
    issuerAndSerialNumber IssuerAndSerialNumber,
    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    encryptedKey EncryptedKey }

  EncryptedKey ::= OCTET STRING

*/
var KeyAgreeRecipientInfo = asn1.define('KeyAgreeRecipientInfo', function() {
    this.seq().obj(
        this.key('version').int(),
        this.key('originator').explicit(0).use(OriginatorIdentifierOrKey),
        this.key('ukm').explicit(1).octstr(),
        this.key('keyEncryptionAlgorithm').use(KeyEncryptionAlgorithmIdentifier),
        this.key('recipientEncryptedKeys').seqof(RecipientEncryptedKey)
    );
});

var RecipientInfo = asn1.define('RecipientInfo', function() {
    this.choice({
        kari: this.implicit(1).use(KeyAgreeRecipientInfo)
    });
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

var Data = asn1.define('Data', function() {
    this.octstr();
});
module.exports.Data = Data;

ContentInfo.contentModel = {
    signedData: SignedData,
    envelopedData: EnvelopedData,
    data: Data,
};


module.exports.ContentInfo = ContentInfo;

var WrapAlgo = asn1.define('WrapAlgo', function() {
    this.seq().obj(
        this.key('algorithm').objid(rfc3280.ALGORITHMS_IDS),
        this.key("parameters").null_()
    );
});

var SharedInfo = asn1.define('SharedInfo', function() {
    this.seq().obj(
        this.key("keyInfo").use(WrapAlgo),
        this.key("entityInfo").optional().explicit(0).octstr(),
        this.key("suppPubInfo").explicit(2).octstr()
    );
});

module.exports.SharedInfo = SharedInfo;

function packSbox(input) {
  const ret = Buffer.alloc(input.length / 2);
  const rows = input.length & 0xF0;
  for (let idx=0; idx<input.length; idx+=2) {
    let retIdx = (rows - 0x10 - (idx & 0xF0)) | idx & 0x0F;
    ret[retIdx >> 1] = input[idx] << 4 | input[idx+1];
  }
  return ret;
}

var defaultSbox = Buffer.from('0102030E060D0B080F0A0C050709000403080B0506040E0A020C0107090F0D0002080907050F000B0C010D0E0A0306040F080E090702000D0C0601050B04030A03080D09060B0F0002050C0A040E01070F0605080E0B0A040C0003070209010D08000C040906070B0203010F050E0A0D0A090D060E0B04050F01030C07000802', 'hex');

module.exports.DEFAULT_SBOX_COMPRESSED = packSbox(defaultSbox);

