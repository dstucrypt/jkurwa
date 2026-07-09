/*
 * PEM helpers: detect, wrap, and unwrap the "-----BEGIN/END ...-----" armor
 * around base64-encoded DER data.
 */
"use strict;";

import { Buffer } from "buffer";
import { b64_decode } from "./base64.js";
import { b64_encode } from "../util/base64.js";

/**
 * Test whether the input looks like PEM (starts with five dashes).
 * @param {string|Uint8Array|Buffer} indata Data to inspect.
 * @returns {boolean|undefined} True if PEM-armored; falsy otherwise.
 */
var is_pem = function (indata) {
  if (indata.constructor === Uint8Array || Buffer.isBuffer(indata)) {
    if (
      indata[0] === 0x2d &&
      indata[1] === 0x2d &&
      indata[2] === 0x2d &&
      indata[3] === 0x2d &&
      indata[4] === 0x2d
    ) {
      return true;
    }
  }
  if (typeof indata === "string") {
    return indata.indexOf("-----") === 0;
  }
};

/**
 * Strip PEM armor and decode the enclosed base64 body to bytes.
 * @param {string|Uint8Array|Buffer} indata PEM text (or byte form of it).
 * @returns {Buffer} The decoded DER bytes.
 */
var from_pem = function (indata) {
  var start, end, ln;
  if (typeof indata !== "string") {
    indata = String.fromCharCode.apply(null, indata);
  }
  indata = indata.split("\n");
  for (start = 0; start < indata.length; start++) {
    ln = indata[start];
    if (ln.indexOf("-----") === 0) {
      start++;
      break;
    }
  }

  for (end = 1; end <= indata.length; end++) {
    ln = indata[indata.length - end];
    if (ln.indexOf("-----") === 0) {
      break;
    }
  }

  // Drop CR left by CRLF line endings; b64_decode would reject it otherwise.
  indata = indata.slice(start, -end).join("").replace(/\r/g, "");
  return b64_decode(indata);
};

/**
 * Decode from PEM if the input is PEM, otherwise return it unchanged.
 * @param {string|Uint8Array|Buffer} indata Possibly PEM-armored data.
 * @returns {Buffer|string|Uint8Array} Decoded bytes, or the original input.
 */
var maybe_pem = function (indata) {
  if (is_pem(indata)) {
    return from_pem(indata);
  }

  return indata;
};

/**
 * Wrap bytes in PEM armor (base64 body, 16-char lines, padded).
 * @param {Uint8Array|Buffer|number[]} data Bytes to encode.
 * @param {string} [desc="PRIVATE KEY"] Label used in the BEGIN/END lines.
 * @returns {string} The PEM-formatted string.
 */
var to_pem = function (data, desc) {
  var begin, end;
  if (desc === undefined) {
    desc = "PRIVATE KEY";
  }
  begin = "-----BEGIN " + desc + "-----";
  end = "-----END " + desc + "-----";

  return [begin, b64_encode(data, { line: 16, pad: true }), end].join("\n");
};

export { from_pem, is_pem, maybe_pem, to_pem };
