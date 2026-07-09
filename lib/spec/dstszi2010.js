/*
 * ASN.1 schema for the Ukrainian DSTSZI-2010 CMS/PKCS#7 profile.
 *
 * This module models the cryptographic message containers used by Ukrainian
 * PKI: PKCS#7 / CMS (RFC 2315, RFC 3852, RFC 5652) SignedData, EnvelopedData
 * and EncryptedData, adapted to the DSTU national algorithm suite — GOST
 * 28147:2009 block cipher, GOST 34.311 (and DSTU 7564 "Kupyna") hashes and
 * DSTU 4145 EC signatures. The DSTSZI-2010 order defined how these standard
 * CMS structures are used with the Ukrainian algorithm OIDs, so the shapes
 * below are mostly the RFC structures wired to DSTU algorithm identifiers via
 * rfc3280.ALGORITHMS_IDS. Structures are defined with asn1.js `define()`.
 */
import asn1 from "asn1.js";
import * as rfc3280 from "./rfc3280.js";
import { Buffer } from "buffer";

// PKCS#7 content-type OIDs, mapping each OID string to a short name. The last
// entry (id-ct-TSTInfo) is an RFC 3161 timestamp token content type, not a
// classic PKCS#7 type.
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
const PKCS7_CONTENT_TYPES = {
  "1 2 840 113549 1 7 1": "data",
  "1 2 840 113549 1 7 2": "signedData",
  "1 2 840 113549 1 7 3": "envelopedData",
  "1 2 840 113549 1 7 4": "signedAndEnvelopedData",
  "1 2 840 113549 1 7 5": "digestData",
  "1 2 840 113549 1 7 6": "encryptedData",
  "1 2 840 113549 1 9 16 1 4": "tstInfo"
};
export { PKCS7_CONTENT_TYPES };

// The outer contentType OBJECT IDENTIFIER of a ContentInfo, resolved to one of
// the PKCS7_CONTENT_TYPES names.
var ContentType = asn1.define("ContentType", function () {
  this.objid(PKCS7_CONTENT_TYPES);
});
export { ContentType };

/**
  http://tools.ietf.org/html/rfc2315#section-7

  ContentInfo ::= SEQUENCE {
     contentType ContentType,
     content
       [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
*/
// Top-level CMS wrapper: a contentType tag plus the [0] EXPLICIT body whose
// concrete shape is chosen at parse time from ContentInfo.contentModel keyed by
// the resolved contentType name (see the contentModel assignment near the end
// of the file).
var ContentInfo = asn1.define("ContentInfo", function () {
  this.seq().obj(
    this.key("contentType").use(ContentType),
    this.key("content")
      .optional()
      .explicit(0)
      .use(function (obj) {
        var model = ContentInfo.contentModel[obj.contentType];
        if (model === undefined) {
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
// Parameters for the GOST 28147:2009 cipher: the initialization vector and an
// optional DKE (the packed S-box / substitution table). When dke is absent the
// default S-box is used (see DEFAULT_SBOX_COMPRESSED below).
var GOST28147Parameters = asn1.define("GOST28147Parameters", function () {
  this.seq().obj(this.key("iv").octstr(), this.key("dke").optional().octstr());
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

// AlgorithmIdentifier for the symmetric content-encryption step. The parameter
// shape is selected from ContentInfo.algoModel by the algorithm OID (e.g.
// GOST28147Parameters for Gost28147-cfb), or NULL when absent.
var ContentEncryptionAlgorithmIdentifier = asn1.define(
  "ContentEncryptionAlgorithmIdentifier",
  function () {
    this.seq().obj(
      this.key("algorithm").objid(ContentInfo.algoModel.IDS),
      this.key("parameters").choice({
        null_: this.null_(),
        params: this.use(function (obj) {
          const ret = ContentInfo.algoModel[obj.algorithm];
          if (!ret) {
            throw new Error("No spec for", obj.algorithm);
          }
          return ret;
        })
      })
    );
  }
);

export { ContentEncryptionAlgorithmIdentifier };

// Hash algorithm of a signature (e.g. GOST 34.311 or DSTU 7564 Kupyna).
var DigestAlgorithmIdentifier = asn1.define(
  "DigestAlgorithmIdentifier",
  function () {
    this.use(rfc3280.AlgorithmIdentifier);
  }
);

// SignedData.digestAlgorithms: the SET of hash algorithms used by signers.
var DigestAlgorithmIdentifiers = asn1.define(
  "DigestAlgorithmIdentifiers",
  function () {
    this.setof(DigestAlgorithmIdentifier);
  }
);

// AlgorithmIdentifier for the key-wrap step of key agreement (GOST 28147 key
// wrap); the parameters carry the nested WrapAlgo describing the wrapped key's
// algorithm.
var KeyEncryptionAlgorithmIdentifier = asn1.define(
  "KeyEncryptionAlgorithmIdentifier",
  function () {
    this.seq().obj(
      this.key("algorithm").objid(rfc3280.ALGORITHMS_IDS),
      this.key("parameters").use(WrapAlgo)
    );
  }
);

/**
  http://tools.ietf.org/html/rfc2315#section-6.7

  IssuerAndSerialNumber ::= SEQUENCE {
    issuer Name,
    serialNumber CertificateSerialNumber }

*/
var IssuerAndSerialNumber = asn1.define("IssuerAndSerialNumber", function () {
  this.seq().obj(
    this.key("issuer").use(rfc3280.Name),
    this.key("serialNumber").use(rfc3280.CertificateSerialNumber)
  );
});

export { IssuerAndSerialNumber };

/**
  Attribute: A type that contains an attribute type (specified by
  object identifier) and one or more attribute values. This type is
  defined in X.501.

  Attribute ::= SEQUENCE {
  type AttributeType ( { SupportedAttributes } ),
  values SET SIZE (1 .. MAX) OF AttributeValue ( { SupportedAttributes}{@type})}

*/
var Attribute = asn1.define("Attribute", function () {
  this.seq().obj(
    this.key("type").use(rfc3280.AttributeType),
    this.key("values").setof(rfc3280.AttributeValue)
  );
});

// SET OF Attribute, used for the (un)authenticated attributes of a SignerInfo.
var Attributes = asn1.define("Attributes", function () {
  this.setof(Attribute);
});
export { Attributes };

// Signature algorithm applied over the digest, i.e. the DSTU 4145 EC signature.
var DigestEncryptionAlgorithmIdentifier = asn1.define(
  "DigestEncryptionAlgorithmIdentifier",
  function () {
    this.use(rfc3280.AlgorithmIdentifier);
  }
);

var SubjectKeyIdentifier = asn1.define("SubjectKeyIdentifier", function () {
  this.octstr();
});

// How a signer is referenced: by issuer name + serial, or by [0] key identifier.
var SignerIdentifier = asn1.define("SignerIdentifier", function () {
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
var SignerInfo = asn1.define("SignerInfo", function () {
  this.seq().obj(
    this.key("version").int(),
    this.key("sid").use(SignerIdentifier),
    this.key("digestAlgorithm").use(DigestAlgorithmIdentifier),
    this.key("authenticatedAttributes").optional().implicit(0).use(Attributes),
    this.key("digestEncryptionAlgorithm").use(
      DigestEncryptionAlgorithmIdentifier
    ),
    this.key("encryptedDigest").octstr(),
    this.key("unauthenticatedAttributes").optional().implicit(1).use(Attributes)
  );
});

var SignerInfos = asn1.define("SignerInfos", function () {
  this.setof(SignerInfo);
});

// SignedData.certificates: the bag of signer/CA certificates carried inline.
var Certificates = asn1.define("Certificates", function () {
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
var SignedData = asn1.define("SignedData", function () {
  this.seq().obj(
    this.key("version").int(),
    this.key("digestAlgorithms").use(DigestAlgorithmIdentifiers),
    this.key("contentInfo").use(ContentInfo),
    this.key("certificate").optional().implicit(0).use(Certificates),
    this.key("crls").optional().implicit(1).set(), // NOT PARSED
    this.key("signerInfos").use(SignerInfos)
  );
});

// Reference to a recipient by their subjectKeyIdentifier plus optional date/
// other qualifiers, used inside key-agreement recipient info.
var RecipientKeyIdentifier = asn1.define("RecipientKeyIdentifier", function () {
  this.seq().obj(
    this.key("subjectKeyIdentifier").octstr(),
    this.key("date").use(rfc3280.Time).optional(),
    this.key("other").optional().any()
  );
});

// How a key-agreement recipient is identified: by issuer+serial or [0] key id.
var KeyAgreeRecipientIdentifier = asn1.define(
  "KeyAgreeRecipientIdentifier",
  function () {
    this.choice({
      issuerAndSerialNumber: this.use(IssuerAndSerialNumber),
      rKeyId: this.implicit(0).use(RecipientKeyIdentifier)
    });
  }
);

// A per-recipient wrapped content-encryption key together with the identifier
// of the recipient it is encrypted for.
var RecipientEncryptedKey = asn1.define("RecipientEncryptedKey", function () {
  this.seq().obj(
    this.key("rid").use(KeyAgreeRecipientIdentifier),
    this.key("encryptedKey").octstr()
  );
});

/**
  http://tools.ietf.org/html/rfc2315#section-6.7

  IssuerAndSerialNumber ::= SEQUENCE {
    issuer Name,
    serialNumber CertificateSerialNumber }
*/
// Originator (sender) info for EnvelopedData. Note: this simplified profile
// carries only an IssuerAndSerialNumber reference under the "certificates" key.

// The originator's ephemeral EC public key used for the key-agreement.
var OriginatorPublicKey = asn1.define("OriginatorPublicKey", function () {
  this.seq().obj(
    this.key("algorithm").use(rfc3280.AlgorithmIdentifier),
    this.key("publicKey").bitstr()
  );
});

// How the originator is conveyed: by issuer+serial, [0] key id, or [1] an
// inline ephemeral public key (originatorKey) for the DH key agreement.
var OriginatorIdentifierOrKey = asn1.define(
  "OriginatorIdentifierOrKey",
  function () {
    this.seq().choice({
      issuerAndSerialNumber: this.use(IssuerAndSerialNumber),
      subjectKeyIdentifier: this.implicit(0).use(SubjectKeyIdentifier),
      originatorKey: this.implicit(1).use(OriginatorPublicKey)
    });
  }
);

/**
  https://tools.ietf.org/html/rfc5652#section-6.2

  RecipientInfo ::= SEQUENCE {
    version Version,
    issuerAndSerialNumber IssuerAndSerialNumber,
    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
    encryptedKey EncryptedKey }

  EncryptedKey ::= OCTET STRING

*/
// KeyAgreeRecipientInfo (CMS "kari"): recipients whose content-encryption key
// is delivered via EC Diffie-Hellman key agreement. `ukm` is the user keying
// material (random) mixed into the KDF; the wrapped keys are one per recipient.
var KeyAgreeRecipientInfo = asn1.define("KeyAgreeRecipientInfo", function () {
  this.seq().obj(
    this.key("version").int(),
    this.key("originator").explicit(0).use(OriginatorIdentifierOrKey),
    this.key("ukm").explicit(1).octstr(),
    this.key("keyEncryptionAlgorithm").use(KeyEncryptionAlgorithmIdentifier),
    this.key("recipientEncryptedKeys").seqof(RecipientEncryptedKey)
  );
});

// RecipientInfo CHOICE. This profile only supports the [1] key-agreement
// variant (kari); the RSA-style ktri and other variants are not modelled.
var RecipientInfo = asn1.define("RecipientInfo", function () {
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
var EncryptedContentInfo = asn1.define("EncryptedContentInfo", function () {
  this.seq().obj(
    this.key("contentType").objid(PKCS7_CONTENT_TYPES),
    this.key("contentEncryptionAlgorithm").use(
      ContentEncryptionAlgorithmIdentifier
    ),
    this.key("encryptedContent").optional().implicit(0).octstr()
  );
});

/**
  http://tools.ietf.org/html/rfc2315#section-10.1

  EnvelopedData ::= SEQUENCE {
    version Version,
    recipientInfos RecipientInfos,
    encryptedContentInfo EncryptedContentInfo }
*/
var EnvelopedData = asn1.define("EnvelopedData", function () {
  this.seq().obj(
    this.key("version").int(),
    this.key("recipientInfos").setof(RecipientInfo),
    this.key("encryptedContentInfo").use(EncryptedContentInfo)
  );
});

/**
  https://www.rfc-editor.org/rfc/rfc2315#section-13

  EncryptedData ::= SEQUENCE {
     version Version,
     encryptedContentInfo EncryptedContentInfo }
*/

var EncryptedData = asn1.define("EncryptedData", function () {
  this.seq().obj(
    this.key("version").int(),
    this.key("encryptedContentInfo").use(EncryptedContentInfo)
  );
});

// PKCS#7 "data" content: an opaque OCTET STRING payload.
var Data = asn1.define("Data", function () {
  this.octstr();
});
export { Data };

// Wire ContentInfo's polymorphic body: map each resolved content-type name to
// the concrete structure used to parse the [0] EXPLICIT content.
ContentInfo.contentModel = {
  signedData: SignedData,
  envelopedData: EnvelopedData,
  encryptedData: EncryptedData,
  data: Data
};
// Map content-encryption algorithm names to their parameter structures, and
// expose the OID lookup table used to resolve those algorithm names.
ContentInfo.algoModel = {
  "Gost28147-cfb": GOST28147Parameters
};
ContentInfo.algoModel.IDS = Object.assign({}, rfc3280.ALGORITHMS_IDS);

export { ContentInfo };

// Identifier of the key-wrap algorithm (algorithm OID + NULL parameters) that
// describes the wrapped content-encryption key inside a KeyEncryptionAlgorithm.
var WrapAlgo = asn1.define("WrapAlgo", function () {
  this.seq().obj(
    this.key("algorithm").objid(rfc3280.ALGORITHMS_IDS),
    this.key("parameters").null_()
  );
});

// SharedInfo fed to the DSTU/GOST key-derivation function during key agreement.
// suppPubInfo [2] conventionally carries the desired key length; entityInfo [0]
// is optional extra context.
var SharedInfo = asn1.define("SharedInfo", function () {
  this.seq().obj(
    this.key("keyInfo").use(WrapAlgo),
    this.key("entityInfo").optional().explicit(0).octstr(),
    this.key("suppPubInfo").explicit(2).octstr()
  );
});

export { SharedInfo };

/**
 * Compress a GOST 28147 S-box (DKE) from its expanded nibble-per-byte form into
 * the packed two-nibbles-per-byte layout used on the wire. The bit twiddling
 * reorders rows (high nibble of the index) while preserving column order, so
 * that the 128-nibble table becomes a 64-byte buffer.
 *
 * @param {Buffer} input expanded S-box, one substitution nibble per byte
 * @returns {Buffer} packed S-box, two nibbles per byte
 */
function packSbox(input) {
  const ret = Buffer.alloc(input.length / 2);
  const rows = input.length & 0xf0;
  for (let idx = 0; idx < input.length; idx += 2) {
    let retIdx = (rows - 0x10 - (idx & 0xf0)) | (idx & 0x0f);
    ret[retIdx >> 1] = (input[idx] << 4) | input[idx + 1];
  }
  return ret;
}

// The default GOST 28147 S-box used by Ukrainian PKI when a message carries no
// explicit DKE; stored expanded (one nibble per byte) and packed below.
var defaultSbox = Buffer.from(
  "0102030E060D0B080F0A0C050709000403080B0506040E0A020C0107090F0D0002080907050F000B0C010D0E0A0306040F080E090702000D0C0601050B04030A03080D09060B0F0002050C0A040E01070F0605080E0B0A040C0003070209010D08000C040906070B0203010F050E0A0D0A090D060E0B04050F01030C07000802",
  "hex"
);

// Packed (wire-format) default S-box, exported for the cipher implementation.
export const DEFAULT_SBOX_COMPRESSED = packSbox(defaultSbox);
