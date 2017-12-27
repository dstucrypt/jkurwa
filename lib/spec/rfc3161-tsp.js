var asn1 = require('asn1.js');
var dstszi2010 = require('./dstszi2010');
var rfc3280 = require('./rfc3280');

/*

TimeStampReq ::= SEQUENCE  {
   version                      INTEGER  { v1(1) },
   messageImprint               MessageImprint,
     --a hash algorithm OID and the hash value of the data to be time-stamped
   reqPolicy             TSAPolicyId              OPTIONAL,
   nonce                 INTEGER                  OPTIONAL,
   certReq               BOOLEAN                  DEFAULT FALSE,
   extensions            [0] IMPLICIT Extensions  OPTIONAL  }

*/

var TimeStampReq = asn1.define('TimeStampReq', function () {
  this.seq().obj(
    this.key('version').int({1: 'v1'}),
    this.key('messageImprint').use(MessageImprint)
  );
});

var MessageImprint = asn1.define('MessageImprint', function () {
  this.seq().obj(
    this.key('hashAlgorithm').use(rfc3280.AlgorithmIdentifier),
    this.key('hashedMessage').octstr()
  );
});

/*
   TimeStampResp ::= SEQUENCE  {
      status                  PKIStatusInfo,
      timeStampToken          TimeStampToken     OPTIONAL  }
*/

var TimeStampResp = asn1.define('TimeStampResp', function () {
	this.seq().obj(
		this.key('status').use(PKIStatusInfo),
    this.key('timeStampToken').use(dstszi2010.ContentInfo)
  );
});

var PKIStatusInfo = asn1.define('PKIStatusInfo', function () {
	this.seq().obj(
		this.key('status').int({
			0: 'granted',
			1: 'grantedWithMods',
	    2: 'rejection',
      3: 'waiting',
      4: 'revocationWarning',
    }),
    this.key('statusString').any().optional(),
    this.key('failInfo').any().optional()
  );
});


var TSTInfoStr = asn1.define('TSTInfoStr', function () {
  this.octstr();
});

var TSTInfo = asn1.define('TSTInfoSeq', function () {
  this.seq().obj(
    this.key('version').int({1: 'v1'}),
    this.key('policy').objid(),
    this.key('messageImprint').use(MessageImprint),
    this.key('serialNumber').int(),
    this.key('genTime').gentime(),
    this.key('accuracy').seq().optional(),
    this.key('ordering').bool().optional().def(false),
    this.key('nonce').int().optional(),
    this.key('tsa').use('GeneralName').optional(),
    this.key('extensions').any().optional()
  );
});

dstszi2010.ContentInfo.contentModel.tstInfo = TSTInfoStr;

module.exports = {
  TimeStampReq: TimeStampReq,
  TimeStampResp: TimeStampResp,
  TSTInfo: TSTInfo,
};
