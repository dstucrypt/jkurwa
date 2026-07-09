/*
 * High-level signing with jk.Box.
 *
 *   node examples/box-sign.js
 *
 * Box ties keys, certificates and the hash/cipher `algo` together. `pipe()`
 * runs a list of operations ("sign", "encrypt") and returns the encoded result.
 */
import fs from "fs";
import gost89 from "gost89";
import * as jk from "../lib/index.js";

const asset = name => new URL(`../test/data/${name}`, import.meta.url);

const box = new jk.Box({ algo: gost89.compat.algos() });
box.load({
  priv: jk.Priv.from_asn1(fs.readFileSync(asset("PRIV1.cer"))),
  cert: jk.Certificate.from_asn1(fs.readFileSync(asset("SELF_SIGNED1.cer")))
});

// A plain CMS signedData message. The hash is chosen from the signing
// certificate automatically (GOST cert -> GOST 34.311, Kupyna cert -> Kupyna).
const signed = await box.pipe(
  Buffer.from("Hello via Box"),
  [{ op: "sign", time: 1540236305 }],
  {}
);
fs.writeFileSync("box-signed.p7", signed);
console.log(`wrote box-signed.p7 (${signed.length} bytes)`);

// Tax-office transport envelope — add `tax: true` and pass the headers as opts:
//
//   const transport = await box.pipe(
//     Buffer.from("Hello via Box"),
//     [{ op: "sign", time: 1540236305, tax: true }],
//     { EDRPOU: "1234567891", RCV_EMAIL: "user@tax.mail.com", DOC_TYPE: "3" }
//   );
//
// Force a specific hash for every sign() with `new jk.Box({ algo, hashMethod:
// "kupyna" })`, or per operation with `{ op: "sign", hash: "kupyna" }`.
