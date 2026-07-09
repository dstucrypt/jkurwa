/*
 * Sign a document with DSTU 4145 (GOST 34.311 hash) and write a CMS
 * `signedData` message. Run from anywhere:
 *
 *   node examples/sign.js
 *
 * (The library sources use extensionless imports, so run this through the
 * bundler/your app; it is written as a faithful, copy-pasteable illustration.)
 */
import fs from "fs";
import gost89 from "gost89";
import * as jk from "../lib/index.js";

const asset = name => new URL(`../test/data/${name}`, import.meta.url);

const algo = gost89.compat.algos();
const priv = jk.Priv.from_asn1(fs.readFileSync(asset("PRIV1.cer")));
const cert = jk.Certificate.from_asn1(
  fs.readFileSync(asset("SELF_SIGNED1.cer"))
);

const data = Buffer.from("Hello, DSTU 4145!");

const message = new jk.models.Message({
  type: "signedData",
  cert,
  data,
  hash: algo.hash,
  signTime: Math.floor(Date.now() / 1000),
  signer: priv
});

const der = message.as_asn1();
fs.writeFileSync("signed.p7", der);
console.log(`wrote signed.p7 (${der.length} bytes)`);

// Wrap into the tax-office transport envelope instead:
//   const transport = message.as_transport({
//     EDRPOU: "1234567891",
//     RCV_EMAIL: "user@tax.mail.com",
//     DOC_TYPE: "3",
//   });
