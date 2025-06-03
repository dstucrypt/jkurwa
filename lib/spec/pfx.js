import asn1 from "asn1.js";
import pbes2 from "./pbes.js";
import * as dstszi2010 from "./dstszi2010.js";
import * as rfc3280 from "./rfc3280.js";

const OID = {
  "1 2 840 113549 1 12 10 1 2": "pkcs-12-pkcs-8ShroudedKeyBag",
  "1 2 840 113549 1 12 10 1 3": "pkcs-12-certBag",
  "1 2 840 113549 1 12 10 1 5": "secretBag"
};

const CertBag = asn1.define("CertBag", function() {
  this.seq().obj(
    this.key("id").objid({
      "1 2 840 113549 1 9 22 1": "x509Certificate"
    }),
    this.key("certValue")
      .explicit(0)
      .octstr()
  );
});

// This wraps the bag with unknown id.
// Judging from the id 19398 it's another IIT trap they don't want
// anyone to be able to parse.

const SecretBag = asn1.define("SecretBag", function() {
  this.seq().obj(
    this.key("id").objid(dstszi2010.PKCS7_CONTENT_TYPES),
    this.key("content").any() // this looks like encrypted pkcs7 data
  );
});

const BagModels = {
  "pkcs-12-pkcs-8ShroudedKeyBag": pbes2,
  "pkcs-12-certBag": CertBag,
  secretBag: SecretBag
};

const SafeBag = asn1.define("SafeContents", function() {
  this.seq().obj(
    this.key("bagId").objid(OID),
    this.key("bagValue")
      .explicit(0)
      .use(function(ob) {
        if (!BagModels[ob.bagId]) {
          throw new Error("Unknown bag id", ob.bagId);
        }
        return BagModels[ob.bagId];
      }),
    this.key("bagAttributes")
      .set()
      .optional()
  );
});

const SafeContents = asn1.define("SafeContents", function() {
  return this.seqof(SafeBag);
});

const Bags = asn1.define("ContentInfo", function() {
  this.seqof(dstszi2010.ContentInfo);
});

function pfx_parse(data) {
  const messages = Bags.decode(data.slice(30), "der");
  return messages
    .filter(
      msg => msg.contentType === "data" || msg.contentType === "encryptedData"
    )
    .map(msg => {
      if (msg.contentType === "encryptedData") {
        return pbes2.obj_parse(msg.content.encryptedContentInfo);
      }

      const bags = SafeContents.decode(msg.content, "der");
      return bags
        .filter(bag => bag.bagId === "pkcs-12-pkcs-8ShroudedKeyBag")
        .map(bag => pbes2.obj_parse(bag.bagValue));
    })
    .reduce((acc, keys) => acc.concat(keys), []);
}

function certbags_from_asn1(data) {
  const bags = SafeContents.decode(data, "der");
  return bags.map(bag => bag.bagValue.certValue);
}

export { pfx_parse, certbags_from_asn1 };
