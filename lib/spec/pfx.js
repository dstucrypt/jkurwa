const asn1 = require('asn1.js');
const pbes2 = require('./pbes');
const dstszi2010 = require('./dstszi2010');

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

const Bags = asn1.define('ContentInfo', function () {
  this.seqof(dstszi2010.ContentInfo);
});

function pfx_parse (data) {
  const messages = Bags.decode(data.slice(30), 'der');
  return messages
    .filter(msg => msg.contentType ==='data')
    .map(msg => {
      const bags = SafeContents.decode(msg.content, 'der')
      return bags.map(bag=> pbes2.obj_parse(bag.bagValue));
    }).reduce((acc, keys)=> acc.concat(keys), []);
}

module.exports = { pfx_parse };
