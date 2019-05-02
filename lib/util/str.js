const asn1 = require("asn1.js");

function encodeUtf8Str(input, encoder) {
  const UTF8STR = asn1.define("UTF8STR", function UTF8STR() {
    this.utf8str();
  });
  return UTF8STR.encode(input, encoder);
}

function str(input) {
  const STR = asn1.define("STR", function STR() {
    this.octstr();
  });
  return STR.encode(input, "der");
}

module.exports = { str, encodeUtf8Str };
