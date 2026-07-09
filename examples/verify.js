/*
 * Parse a CMS `signedData` message and verify its signature.
 * Produce the input first with `node examples/sign.js`, then:
 *
 *   node examples/verify.js
 */
import fs from "fs";
import gost89 from "gost89";
import * as jk from "../lib/index.js";

const algo = gost89.compat.algos();

const message = new jk.models.Message(fs.readFileSync("signed.p7"));

console.log("content:      ", message.content.toString());
console.log("digest OID:   ", message.digestAlgo);

// verify() picks the embedded certificate when no lookup is supplied, checks
// the signed attributes (message digest, signing time) and the DSTU 4145
// signature. It does NOT validate the certificate chain unless a CA list and
// lookup are provided — see jk.Box + box.loadCAs() for that.
console.log("signature ok: ", message.verify(algo.hash));
