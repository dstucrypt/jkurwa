var asn1 = require('asn1.js'),
    rfc3280 = require('./rfc3280'),
    rfc4210 = require('./rfc4210-cmp.js');

/*
OCSPRequest     ::=     SEQUENCE {
       tbsRequest                  TBSRequest,
       optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
*/

var OCSPRequest = asn1.define('OCSPRequest', function () {
    this.seq().obj(
        this.key('tbsRequest').use(TBSRequest),
        this.key('optionalSignature').optional().explicit(0).use(Signature)
    );
});


/*
   TBSRequest      ::=     SEQUENCE {
       version             [0]     EXPLICIT Version DEFAULT v1,
       requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
       requestList                 SEQUENCE OF Request,
       requestExtensions   [2]     EXPLICIT Extensions OPTIONAL }
*/
var TBSRequest = asn1.define('TBSRequest', function () {
    this.seq().obj(
        this.key('version').explicit(0).use(Version).def('v1'),
        this.key('requestorName').explicit(1).optional().use(rfc4210.GeneralName),
        this.key('requestList').seqof(Request),
        this.key('requestExtensions').explicit(2).optional().use(rfc3280.Extensions)
    );
});


/*
   Signature       ::=     SEQUENCE {
       signatureAlgorithm      AlgorithmIdentifier,
       signature               BIT STRING,
       certs               [0] EXPLICIT SEQUENCE OF Certificate
   OPTIONAL}
*/
var Signature = asn1.define('Signature', function () {
    this.seq().obj(
        this.key('signatureAlgorithm').use(rfc3280.AlgorithmIdentifier),
        this.key('signature').bitstr(),
        this.key('certs').explicit(0).optional().seqof(rfc3280.Certificate)
    );
});

/*
   Version         ::=             INTEGER  {  v1(0) }
*/
var Version = asn1.define('Version', function () {
    this.int({0: 'v1'});
});

/*
       CertificateSerialNumber  ::=  INTEGER
*/
var CertificateSerialNumber = asn1.define('CertificateSerialNumber', function () {
    this.int();
});

/*
   Request         ::=     SEQUENCE {
       reqCert                     CertID,
       singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
*/
var Request = asn1.define('Request', function () {
    this.seq().obj(
        this.key('reqCert').use(CertID),
        this.key('singleRequestExtensions').explicit(0).optional().use(rfc3280.Extensions)
    );
});

/*
   CertID          ::=     SEQUENCE {
       hashAlgorithm       AlgorithmIdentifier,
       issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
       issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
       serialNumber        CertificateSerialNumber }
*/
var CertID = asn1.define('CertID', function () {
    this.seq().obj(
        this.key('hashAlgorithm').use(rfc3280.AlgorithmIdentifier),
        this.key('issuerNameHash').octstr(),
        this.key('issuerKeyHash').octstr(),
        this.key('serialNumber').use(CertificateSerialNumber)
    );
});

/*
   OCSPResponse ::= SEQUENCE {
      responseStatus         OCSPResponseStatus,
      responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
 */

var OCSPResponse = asn1.define('OCSPResponse', function () {
    this.seq().obj(
        this.key('responseStatus').use(OCSPResponseStatus),
        this.key('responseBytes').optional().explicit(0).use(ResponseBytes)
    );
});

/*
   OCSPResponseStatus ::= ENUMERATED {
       successful            (0),  --Response has valid confirmations
       malformedRequest      (1),  --Illegal confirmation request
       internalError         (2),  --Internal error in issuer
       tryLater              (3),  --Try again later
                                   --(4) is not used
       sigRequired           (5),  --Must sign the request
       unauthorized          (6)   --Request unauthorized
   } */

var OCSPResponseStatus = asn1.define('OCSPResponseStatus', function () {
    this.enum({
        0: 'successful',
        1: 'malformedRequest',
        2: 'internalError',
        3: 'tryLater',
        5: 'sigRequired',
        6: 'unauthorized'
    });
});

/*
   ResponseBytes ::=       SEQUENCE {
       responseType   OBJECT IDENTIFIER,
       response       OCTET STRING } 
*/

var ResponseBytes = asn1.define('ResponseBytes', function () {
    this.seq().obj(
        this.key('responseType').objid(),
        this.key('response').octstr()
    );
});

/*
    BasicOCSPResponse       ::= SEQUENCE {
      tbsResponseData      ResponseData,
      signatureAlgorithm   AlgorithmIdentifier,
      signature            BIT STRING,
      certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
*/

var BasicOCSPResponse = asn1.define('BasicOCSPResponse', function () {
    this.seq().obj(
        this.key('tbsResponseData').use(ResponseData),
        this.key('signatureAlgorithm').use(rfc3280.AlgorithmIdentifier),
        this.key('signature').bitstr(),
        this.key('certs').optional().explicit(0).seqof(rfc3280.Certificate)
    );
});

/*
   ResponseData ::= SEQUENCE {
      version              [0] EXPLICIT Version DEFAULT v1,
      responderID              ResponderID,
      producedAt               GeneralizedTime,
      responses                SEQUENCE OF SingleResponse,
      responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
 */

var ResponseData = asn1.define('ResponseData', function () {
    this.seq().obj(
        this.key('version').explicit(0).use(Version).def('v1'),
        this.key('responderID').use(ResponderID),
        this.key('producedAt').gentime(),
        this.key('responses').seqof(SingleResponse),
        this.key('responseExtensions').optional().explicit(1).use(rfc3280.Extensions)
    );
});

/*
   ResponderID ::= CHOICE {
      byName               [1] Name,
      byKey                [2] KeyHash }
*/

var ResponderID = asn1.define('ResponderID', function () {
    this.choice({
        byName: this.explicit(1).use(rfc3280.Name),
        byKey: this.explicit(2).use(KeyHash)
    });
});

var KeyHash = asn1.define('KeyHash', function () {
    this.octstr();
});

/*
   SingleResponse ::= SEQUENCE {
      certID                       CertID,
      certStatus                   CertStatus,
      thisUpdate                   GeneralizedTime,
      nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
      singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
*/

var SingleResponse = asn1.define('SingleResponse', function () {
    this.seq().obj(
        this.key('certID').use(CertID),
        this.key('certStatus').use(CertStatus),
        this.key('thisUpdate').gentime(),
        this.key('nextUpdate').optional().explicit(0).gentime(),
        this.key('singleExtensions').optional().explicit(1).use(rfc3280.Extensions)
    );
});

/*
   CertStatus ::= CHOICE {
       good        [0]     IMPLICIT NULL,
       revoked     [1]     IMPLICIT RevokedInfo,
       unknown     [2]     IMPLICIT UnknownInfo }
*/

var CertStatus = asn1.define('CertStatus', function () {
    this.choice({
        good: this.implicit(0).null_(),
        revoked: this.implicit(1).use(RevokedInfo),
        unknown: this.implicit(2).use(UnknownInfo)
    });
});

/*
   RevokedInfo ::= SEQUENCE {
       revocationTime              GeneralizedTime,
       revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
    */

var RevokedInfo = asn1.define('RevokedInfo', function () {
    this.seq().obj(
        this.key('revocationTime').gentime(),
        this.key('revocationReason').optional().explicit(0).use(rfc3280.CRLReason)
    );
});

/*
   UnknownInfo ::= NULL -- this can be replaced with an enumeration
*/

var UnknownInfo = asn1.define('UnknownInfo', function () {
    this.null_();
});

module.exports = {
    OCSPRequest: OCSPRequest,
    OCSPResponse: OCSPResponse,
    BasicOCSPResponse: BasicOCSPResponse,
};
