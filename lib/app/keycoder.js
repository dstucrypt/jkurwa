import asn1 from "asn1.js";
import { Buffer } from "buffer";
import * as pbes2 from "../spec/pbes";
import * as pfx from "../spec/pfx";
import { enc_parse } from "../spec/keystore";
import * as models from "../models/index";
import * as pem from "../util/pem";
import * as util from "../util";

class Keycoder {
  constructor() {
    console.warn(
      "Keycoder instances are deprecated. Use jk.guess_parse() to parse keys"
    );
  }

  is_valid(indata) {
    return indata[0] === 0x30 && (indata[1] & 0x80) === 0x80;
  }

  is_pem(indata) {
    return pem.is_pem(indata);
  }

  maybe_pem(indata) {
    return pem.maybe_pem(indata);
  }

  parse(indata) {
    return guess_parse(indata);
  }
}

function privkey_parse(data) {
  return models.Priv.from_asn1(data, true);
}

function cert_parse(data) {
  return models.Certificate.from_asn1(data);
}

const parsers = [
  enc_parse,
  pbes2.pbes2_parse,
  pfx.pfx_parse,
  privkey_parse,
  cert_parse
];

function guess_parse(indata) {
  if (!Buffer.isBuffer(indata)) {
    indata = Buffer.from(indata, "binary");
  }

  indata = pem.maybe_pem(indata);

  for (const parser of parsers) {
    try {
      return parser(indata);
    } catch (ignore) {}
  }

  throw new Error("Unknown format");
}

export default Keycoder;
export { guess_parse };
