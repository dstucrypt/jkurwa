const asn1 = require('asn1.js');
const pbes2 = require('./pbes');
const dstszi2010 = require('./dstszi2010');

const OID = {
  '1 2 840 113549 1 12 10 1 2': 'pkcs-12-pkcs-8ShroudedKeyBag',
  '1 2 840 113549 1 12 10 1 5': 'secretBag',
  '1 3 6 1 4 1 19398 2 12 1': 'ignore unknwon bag',
};


const ContentInfo = asn1.define('ContentInfo', function () {
  this.seq().obj(
    this.key("id").objid(dstszi2010.PKCS7_CONTENT_TYPES),
    this.key("content").any(),
  );
});

const BagWrap = asn1.define('BagWrap', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('contents').use(ContentInfo),
  );
});

// This wraps the bag with unknown id.
// Judging from the id 19398 it's another IIT trap they don't want
// anyone to be able to parse.
const UnknownBag = asn1.define('UnknownBag', function () {
  this.seq().obj(
    this.key("id").objid(OID),
    this.key("value").explicit(0).use(BagWrap),
  );
});

const SafeBag = asn1.define('SafeContents', function () {
  this.seq().obj(
    this.key("bagId").objid(OID),
    this.key("bagValue").explicit(0).choice({
      pbes2: this.use(pbes2),
      unknown: this.use(UnknownBag),
    }),
    this.key("bagAttributes").set().optional()
  );
});

const SafeContents = asn1.define('SafeContents', function () {
   return this.seqof(SafeBag);
});

function pfx_parse (data) {
  // we should have 57 bytes of pfx header here
  // which reasonable people would write parser for. later.
  const msg = SafeContents.decode(data.slice(57), "der");
  const supportedBags = msg.filter(bag => bag.bagValue.type === 'pbes2');
  return supportedBags.map(bag=> pbes2.obj_parse(bag.bagValue.value));
}

module.exports = { pfx_parse };
