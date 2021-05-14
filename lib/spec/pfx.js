const asn1 = require('asn1.js');
const pbes2 = require('./pbes');

const OID = {
  '1 2 840 113549 1 12 10 1 2': 'pkcs-12-pkcs-8ShroudedKeyBag',
};

const SafeBag = asn1.define('SafeContents', function () {
  this.seq().obj(
    this.key("bagId").objid(OID),
    this.key("bagValue").explicit(0).use(pbes2),
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
  return msg.map(bag=> pbes2.obj_parse(bag.bagValue));
}

module.exports = { pfx_parse };
