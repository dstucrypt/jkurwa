/*
 * Format-guessing parser for key/certificate blobs.
 *
 * Given raw bytes (or a PEM wrapper) of unknown encoding, `guess_parse` tries
 * each supported container/key format in turn and returns the first that
 * parses: encrypted keystores, PBES2, PKCS#12/PFX, bare private keys and X.509
 * certificates. The `Keycoder` class is a thin, deprecated OO wrapper kept for
 * backwards compatibility — new code should call `guess_parse` directly.
 */
import asn1 from "asn1.js";
import { Buffer } from "buffer";
import * as pbes2 from "../spec/pbes.js";
import * as pfx from "../spec/pfx.js";
import { enc_parse } from "../spec/keystore.js";
import * as models from "../models/index.js";
import * as pem from "../util/pem.js";
import * as util from "../util.js";

/**
 * Deprecated OO wrapper around the format-guessing parser. Retained for
 * backwards compatibility; prefer the standalone `guess_parse`.
 */
class Keycoder {
  constructor() {
    console.warn(
      "Keycoder instances are deprecated. Use jk.guess_parse() to parse keys"
    );
  }

  /**
   * Cheap heuristic: does the blob look like a definite-long-form DER SEQUENCE?
   * @param {Buffer} indata Raw bytes.
   * @returns {boolean} True if it starts with a long-form SEQUENCE tag.
   */
  is_valid(indata) {
    return indata[0] === 0x30 && (indata[1] & 0x80) === 0x80;
  }

  /**
   * @param {Buffer} indata Raw bytes.
   * @returns {boolean} True if the blob is PEM-armored.
   */
  is_pem(indata) {
    return pem.is_pem(indata);
  }

  /**
   * Strip PEM armor if present, returning DER bytes.
   * @param {Buffer} indata Possibly PEM-armored bytes.
   * @returns {Buffer} DER bytes.
   */
  maybe_pem(indata) {
    return pem.maybe_pem(indata);
  }

  /**
   * Parse a key/cert blob of unknown format.
   * @param {Buffer} indata Raw or PEM bytes.
   * @returns {*} Parsed key/cert/keystore model.
   */
  parse(indata) {
    return guess_parse(indata);
  }
}

// Parse a bare DSTU private key from ASN.1 (raw = true).
function privkey_parse(data) {
  return models.Priv.from_asn1(data, true);
}

// Parse an X.509 certificate from ASN.1.
function cert_parse(data) {
  return models.Certificate.from_asn1(data);
}

// Formats attempted in order by guess_parse. Ordering matters: more specific
// encrypted containers are tried before the bare key/cert parsers.
const parsers = [
  enc_parse,
  pbes2.pbes2_parse,
  pfx.pfx_parse,
  privkey_parse,
  cert_parse
];

/**
 * Parse a key/certificate blob of unknown format by trying each known parser
 * until one succeeds.
 * @param {(Buffer|string)} indata Raw or PEM-armored bytes (strings are read as binary).
 * @returns {*} The parsed model from the first matching format.
 * @throws {Error} "Unknown format" if no parser accepts the input.
 */
function guess_parse(indata) {
  if (!Buffer.isBuffer(indata)) {
    indata = Buffer.from(indata, "binary");
  }

  indata = pem.maybe_pem(indata);

  // Try each format; a parser that can't handle the bytes throws, so swallow
  // the error and fall through to the next candidate.
  for (const parser of parsers) {
    try {
      return parser(indata);
    } catch (ignore) {}
  }

  throw new Error("Unknown format");
}

export default Keycoder;
export { guess_parse };
