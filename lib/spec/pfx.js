const asn1 = require('asn1.js');
const pbes2 = require('./pbes');
const dstszi2010 = require('./dstszi2010');
const rfc3280 = require("./rfc3280");

const OID = {
  '1 2 840 113549 1 12 10 1 2': 'pkcs-12-pkcs-8ShroudedKeyBag',
  '1 2 840 113549 1 12 10 1 3': 'pkcs-12-certBag',
};

const CertBag = asn1.define('CertBag', function () {
  this.seq().obj(
    this.key('id').objid({
      '1 2 840 113549 1 9 22 1': 'x509Certificate',
    }),
    this.key("certValue").explicit(0).octstr(),
  );
});
const BagModels = {
  'pkcs-12-pkcs-8ShroudedKeyBag': pbes2,
  'pkcs-12-certBag': CertBag,
};

const SafeBag = asn1.define('SafeContents', function () {
  this.seq().obj(
    this.key("bagId").objid(OID),
    this.key("bagValue").explicit(0).use(function (ob) {
      if (!BagModels[ob.bagId]) {
        throw new Error("Unknown bag id", ob.bagId);
      }
      return BagModels[ob.bagId];
    }),
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
    .filter(msg => msg.contentType ==='data' || msg.contentType === 'encryptedData')
    .map(msg => {
      if (msg.contentType === 'encryptedData') {
        return pbes2.obj_parse(msg.content.encryptedContentInfo);

      }
      const bags = SafeContents.decode(msg.content, 'der')
      return bags.map(bag=> pbes2.obj_parse(bag.bagValue));
    }).reduce((acc, keys)=> acc.concat(keys), []);
}

function certbags_from_asn1(data) {
  const bags = SafeContents.decode(data, 'der');
  return bags.map(bag => bag.bagValue.certValue);
}

module.exports = { pfx_parse, certbags_from_asn1 };
