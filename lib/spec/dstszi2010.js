var asn1 = require('asn1.js'),
    rfc3280 = require('./rfc3280');

var PKCS7_CONTENT_TYPES = {
    "1 2 840 113549 1 7 1": "data",
    "1 2 840 113549 1 7 2": "signedData",
    "1 2 840 113549 1 7 3": "envelopedData",
    "1 2 840 113549 1 7 4": "signedAndEnvelopedData",
    "1 2 840 113549 1 7 5": "digestData",
    "1 2 840 113549 1 7 6": "encryptedData",
};

var ContentInfo = asn1.define('ContentInfo', function() {
    this.seq().obj(
        this.key('contentType').objid(PKCS7_CONTENT_TYPES),
        this.key('content').optional().explicit(0).choice({
            buffer: this.octstr(),
            raw: this.any()
        })
    );
});

var GOST28147Parameters = asn1.define('GOST28147Parameters', function() {
    this.seq().obj(
        this.key('iv').octstr(),
        this.key('dke').octstr()
    )
});

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


var Attribute =  asn1.define('Attribute', function() {
    this.any(); // TO BE DEFINED
});

var Attributes = asn1.define('Attributes', function() {
    this.setof(Attribute);
});

var IssuerAndSerialNumber = asn1.define('IssuerAndSerialNumber', function() {
    this.seq().obj(
        this.key('issuer').use(rfc3280.Name),
        this.key('serialNumber').use(rfc3280.CertificateSerialNumber)
    );
});

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

var SignerInfo = asn1.define('SignerInfo', function() {
    this.seq().obj(
        this.key('version').int(),
        this.key('issuerAndSerialNumber').explicit(0).octstr(),
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

var OriginatorInfo = asn1.define('OriginatorInfo', function() {
    this.implicit(0).seq().obj( // BUG!
        this.key('certificates').use(IssuerAndSerialNumber)
    );
});

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

var EncryptedContentInfo = asn1.define('EncryptedContentInfo', function() {
    this.seq().obj(
        this.key('contentType').objid(PKCS7_CONTENT_TYPES),
        this.key('contentEncryptionAlgorithm').use(ContentEncryptionAlgorithmIdentifier),
        this.key('encryptedContent').optional().implicit(0).octstr()
    );
});

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
