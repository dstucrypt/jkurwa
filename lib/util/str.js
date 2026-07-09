/*
 * Small ASN.1 string encoders built on asn1.js, used to serialize standalone
 * UTF8String and OCTET STRING values.
 */
import asn1 from "asn1.js";

/**
 * Encode a value as an ASN.1 UTF8String.
 * @param {*} input Value accepted by the asn1.js UTF8STR definition.
 * @param {string} encoder asn1.js encoder name (e.g. "der").
 * @returns {Buffer} The encoded UTF8String.
 */
function encodeUtf8Str(input, encoder) {
  const UTF8STR = asn1.define("UTF8STR", function UTF8STR() {
    this.utf8str();
  });
  return UTF8STR.encode(input, encoder);
}

/**
 * DER-encode a value as an ASN.1 OCTET STRING.
 * @param {*} input Value accepted by the asn1.js OCTET STRING definition.
 * @returns {Buffer} The DER-encoded OCTET STRING.
 */
function str(input) {
  const STR = asn1.define("STR", function STR() {
    this.octstr();
  });
  return STR.encode(input, "der");
}

export { str, encodeUtf8Str };
