/*
 * High-level receive/verify with jk.Box.
 *
 *   node examples/box-verify.js
 *
 * `unwrap()` is the inbound counterpart of `pipe()`: it detects the container
 * (transport envelope, signedData, envelopedData), verifies signatures and/or
 * decrypts, and returns the payload.
 */
import fs from "fs";
import gost89 from "gost89";
import * as jk from "../lib/index.js";

const asset = name => new URL(`../test/data/${name}`, import.meta.url);

const box = new jk.Box({ algo: gost89.compat.algos() });

// message.p7 is a signedData with the signer certificate embedded, so no keys
// need to be loaded to read it. Load a CA list with box.loadCAs(...) if you also
// want the certificate chain validated.
const { content, error, signed } = await box.unwrap(
  fs.readFileSync(asset("message.p7"))
);

// `content` is returned once the signature checks out against the signer's
// public key. `signed` becomes truthy only when the signer certificate also
// validates against a trusted chain — load one with box.loadCAs(...) first.
console.log("error:  ", error);
console.log("signed: ", Boolean(signed));
console.log("content:", content && content.toString());
