var asn1 = require('asn1.js'),
    rfc3280 = require('./rfc3280.js');

/*
    OtherName ::= SEQUENCE {
        type-id    OBJECT IDENTIFIER,
        value      [0] EXPLICIT ANY DEFINED BY type-id 
    }
*/

var OtherName = asn1.define('OtherName', function() {
    this.seq().obj(
        this.key('type-id').objid(),
        this.key('value').any()
    );
});
var AnotherName = OtherName;

var IA5String = asn1.define('IA5String', function() {
    this.ia5str();
});

var ORAddress = asn1.define('ORAddress', function() {
    this.any(); // XXX no definition supplied
});

var EDIPartyName = asn1.define('EDIPartyName', function() {
    this.seq().obj(
        this.key('nameAssigner').implicit(0).optional().octstr(),
        this.key('partyName').implicit(1).octstr()
    );
});

var KeyIdentifier = asn1.define('KeyIdentifier', function() {
    this.octstr();
});

var PKIFreeText = asn1.define('PKIFreeText', function() {
    this.octstr(); // XXX UTF8String
});

var InfoTypeAndValue = asn1.define('InfoTypeAndValue', function() {
    this.seq().obj(
        this.key('infoType').objid(),
        this.key('infoValue').optional().any()
    );
});

/*
    GeneralName ::= CHOICE {
     otherName                       [0]     AnotherName,
     rfc822Name                      [1]     IA5String,
     dNSName                         [2]     IA5String,
     x400Address                     [3]     ORAddress,
     directoryName                   [4]     Name,
     ediPartyName                    [5]     EDIPartyName,
     uniformResourceIdentifier       [6]     IA5String,
     iPAddress                       [7]     OCTET STRING,
     registeredID                    [8]     OBJECT IDENTIFIER }
*/

var GeneralName = asn1.define('GeneralName', function() {
    this.choice({
        otherName: this.explicit(0).use(AnotherName),
        rfc822Name: this.explicit(1).use(IA5String),
        dNSName: this.explicit(2).use(IA5String),
        x400Address: this.explicit(3).use(ORAddress),
        directoryName: this.explicit(4).use(rfc3280.Name),
        ediPartyName: this.explicit(5).use(EDIPartyName),
        uniformResourceIdentifier: this.explicit(6).use(IA5String),
        iPAddress: this.explicit(7).octstr(),
        registeredID: this.explicit(8).objid()
    });
});
module.exports.GeneralName = GeneralName;

/*

     http://tools.ietf.org/html/rfc4210#section-5.3.1

     PKIHeader ::= SEQUENCE {
         pvno                INTEGER     { cmp1999(1), cmp2000(2) },
         sender              GeneralName,
         recipient           GeneralName,
         messageTime     [0] GeneralizedTime         OPTIONAL,
         protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
         senderKID       [2] KeyIdentifier           OPTIONAL,
         recipKID        [3] KeyIdentifier           OPTIONAL,
         transactionID   [4] OCTET STRING            OPTIONAL,
         senderNonce     [5] OCTET STRING            OPTIONAL,
         recipNonce      [6] OCTET STRING            OPTIONAL,
         freeText        [7] PKIFreeText             OPTIONAL,
         generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
                             InfoTypeAndValue     OPTIONAL
     }
     PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
*/

var PKIHeader = asn1.define('PKIHeader', function() {
    this.seq().obj(
        this.key('pvno').int().def(2),
        this.key('sender').use(GeneralName),
        this.key('recipient').use(GeneralName),
        this.key('messageTime').optional().implicit(0).gentime(),
        this.key('protectionAlg').optional().implicit(1).use(rfc3280.AlgorithmIdentifier),
        this.key('senderKID').optional().implicit(2).use(KeyIdentifier),
        this.key('recipKID').optional().implicit(3).use(KeyIdentifier),
        this.key('transactionID').optional().implicit(4).octstr(),
        this.key('senderNonce').optional().implicit(5).octstr(),
        this.key('recipNonce').optional().implicit(6).octstr(),
        this.key('freeText').optional().implicit(7).use(PKIFreeText),
        this.key('generalInfo').optional().implicit(8).seqof(InfoTypeAndValue)
    );
});
/* CRMF 

   CertRequest ::= SEQUENCE {
      certReqId     INTEGER,        -- ID for matching request and reply
      certTemplate  CertTemplate, --Selected fields of cert to be issued
      controls      Controls OPTIONAL } -- Attributes affecting issuance

   CertTemplate ::= SEQUENCE {
      version      [0] Version               OPTIONAL,
      serialNumber [1] INTEGER               OPTIONAL,
      signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
      issuer       [3] Name                  OPTIONAL,
      validity     [4] OptionalValidity      OPTIONAL,
      subject      [5] Name                  OPTIONAL,
      publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
      issuerUID    [7] UniqueIdentifier      OPTIONAL,
      subjectUID   [8] UniqueIdentifier      OPTIONAL,
      extensions   [9] Extensions            OPTIONAL }

   OptionalValidity ::= SEQUENCE {
      notBefore  [0] Time OPTIONAL,
      notAfter   [1] Time OPTIONAL } --at least one must be present

   Time ::= CHOICE {
      utcTime        UTCTime,
      generalTime    GeneralizedTime }
*/

var OptionalValidity = asn1.define('OptionalValidity', function() {
    this.seq().obj(
        this.key('notBefore').implicit(0).optional().use(rfc3280.Time),
        this.key('notAfter').implicit(1).optional().use(rfc3280.Time)
    );
});

var CertTemplate = asn1.define('CertTemplate', function() {
    this.seq().obj(
        this.key('version').optional().implicit(0).use(rfc3280.Version),
        this.key('serialNumber').optional().implicit(1).use(rfc3280.CertificateSerialNumber),
        this.key('signingAlg').optional().implicit(2).use(rfc3280.AlgorithmIdentifier),
        this.key('issuer').optional().implicit(3).use(rfc3280.Name),
        this.key('validity').optional().implicit(4).use(OptionalValidity),
        this.key('subject').optional().implicit(5).use(rfc3280.Name),
        this.key('publicKey').optional().implicit(6).use(rfc3280.SubjectPublicKeyInfo),
        this.key('issuerUID').optional().implicit(7).use(rfc3280.UniqueIdentifier),
        this.key('subjectUID').optional().implicit(8).use(rfc3280.UniqueIdentifier),
        this.key('extensions').optional().implicit(8).use(rfc3280.Extensions)
    );
});

var ProofOfPossession = asn1.define('ProofOfPossession', function() {
    this.choice({
        raVerified: this.implicit(0).null_()
    });
});

var CertRequest = asn1.define('CertRequest', function() {
    this.seq().obj(
        this.key('certReqId').int(),
        this.key('certTemplate').use(CertTemplate),
        this.key('controls').optional().any() // XXX
    );
});

var CertReqMsg = asn1.define('CertReqMsg', function() {
    this.seq().obj(
        this.key('certReq').use(CertRequest),
        this.key('popo').optional().use(ProofOfPossession)
    );
});

var CertReqMessages = asn1.define('CertReqMessages', function() {
    this.seqof(CertReqMsg);
});

var PKIStatus = asn1.define('PKIStatus', function() {
    this.int();
});

var PKIStatusInfo = asn1.define('PKIStatusInfo', function() {
    this.seq().obj(
        this.key('status').use(PKIStatus),
        this.key('statusString').use(PKIFreeText).optional(),
        this.key('failInfo').optional().any() //XXX PKIFailureInfo
    );
});

var CertResponse = asn1.define('CertResponse', function() {
    this.seq().obj(
        this.key('certReqId').integer(),
        this.key('status').use(PKIStatusInfo)
    );
});

var CertRepMessage = asn1.define('CertReqMessage', function() {
    this.seq().obj(
        this.key('caPubs').implicit(0).seqof(rfc3280.Certificate).optional(),
        this.key('response').seqof(CertResponse)
    );
});

/*

    PKIBody ::= CHOICE {
          ir       [0]  CertReqMessages,       --Initialization Req
          ip       [1]  CertRepMessage,        --Initialization Resp
          cr       [2]  CertReqMessages,       --Certification Req
          cp       [3]  CertRepMessage,        --Certification Resp
          p10cr    [4]  CertificationRequest,  --PKCS #10 Cert.  Req.
          popdecc  [5]  POPODecKeyChallContent --pop Challenge
          popdecr  [6]  POPODecKeyRespContent, --pop Response
          kur      [7]  CertReqMessages,       --Key Update Request
          kup      [8]  CertRepMessage,        --Key Update Response
          krr      [9]  CertReqMessages,       --Key Recovery Req
          krp      [10] KeyRecRepContent,      --Key Recovery Resp
          rr       [11] RevReqContent,         --Revocation Request
          rp       [12] RevRepContent,         --Revocation Response
          ccr      [13] CertReqMessages,       --Cross-Cert.  Request
          ccp      [14] CertRepMessage,        --Cross-Cert.  Resp
          ckuann   [15] CAKeyUpdAnnContent,    --CA Key Update Ann.
          cann     [16] CertAnnContent,        --Certificate Ann.
          rann     [17] RevAnnContent,         --Revocation Ann.
          crlann   [18] CRLAnnContent,         --CRL Announcement
          pkiconf  [19] PKIConfirmContent,     --Confirmation
          nested   [20] NestedMessageContent,  --Nested Message
          genm     [21] GenMsgContent,         --General Message
          genp     [22] GenRepContent,         --General Response
          error    [23] ErrorMsgContent,       --Error Message
          certConf [24] CertConfirmContent,    --Certificate confirm
          pollReq  [25] PollReqContent,        --Polling request
          pollRep  [26] PollRepContent         --Polling response
    }
*/
var PKIBody = asn1.define('PKIBody', function() {
    this.choice({
        ir: this.implicit(0).optional().use(CertReqMessages),
        ip: this.implicit(1).optional().use(CertRepMessage)
    });
});

var CMPCertificate = asn1.define('CMPCertificate', function() {
    this.use(rfc3280.Certificate);
});

var PKIProtection = asn1.define('PKIProtection', function() {
    this.bitstr();
});

/*
     http://tools.ietf.org/html/rfc4210#section-5.3.1

     PKIMessage ::= SEQUENCE {
         header           PKIHeader,
         body             PKIBody,
         protection   [0] PKIProtection OPTIONAL,
         extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                          OPTIONAL
     }
     PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage

*/

var PKIMessage = asn1.define('PKIMessage', function() {
    this.seq().obj(
        this.key('header').use(PKIHeader),
        this.key('body').use(PKIBody),
        this.key('protection').optional().implicit(0).use(PKIProtection),
        this.key('extraCerts').optional().implicit(1).seqof(CMPCertificate)
    );
});

module.exports.PKIMessage = PKIMessage;
