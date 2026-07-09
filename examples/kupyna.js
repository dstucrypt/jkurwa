/*
 * DSTU 7564:2014 (Kupyna) — hashing and signing.
 *
 *   node examples/kupyna.js
 *
 * Shows the Kupyna hash adapter and a CMS message signed with Kupyna, whose
 * digestAlgorithm carries the Kupyna OID (1.2.804.2.1.1.1.1.2.2.1) instead of
 * GOST 34.311.
 */
import fs from "fs";
import * as jk from "../lib/index.js";
import * as kupyna from "../lib/util/kupyna.js";

const asset = name => new URL(`../test/data/${name}`, import.meta.url);

// --- Hashing ---------------------------------------------------------------
const hash = kupyna.algos().hash; // Kupyna-256, tagged with .algo = "Dstu7564-256"

console.log("Kupyna-256(''):", hash(Buffer.alloc(0)).toString("hex"));
// official DSTU 7564 vector: cd5101d1ccdf0d1d1f4ada56e888cd724ca1a0838a3521e7131d4fb78d0f5eb6
console.log("digest OID tag:", hash.algo);
console.log("Kupyna-512(''):", kupyna.hash512(Buffer.alloc(0)).toString("hex"));

// --- Signing with Kupyna ---------------------------------------------------
const priv = jk.Priv.from_asn1(fs.readFileSync(asset("PRIV1.cer")));
const cert = jk.Certificate.from_asn1(fs.readFileSync(asset("SELF_SIGNED1.cer")));

const message = new jk.models.Message({
  type: "signedData",
  cert,
  data: Buffer.from("Signed with Kupyna"),
  hash, // <- pass the Kupyna hash instead of gost89's algo.hash
  signTime: Math.floor(Date.now() / 1000),
  signer: priv,
});

console.log(
  "digest OID in CMS:",
  message.wrap.content.digestAlgorithms[0].algorithm // => "Dstu7564-256"
);
fs.writeFileSync("signed-kupyna.p7", message.as_asn1());
console.log("wrote signed-kupyna.p7");

/*
 * With the high-level Box the hash is chosen automatically from the signing
 * certificate (Kupyna cert -> Kupyna, GOST cert -> GOST 34.311); you can also
 * force it:
 *
 *   const box = new jk.Box({ algo, hashMethod: "kupyna" });
 *   await box.sign(data, null, null, { hash: "kupyna" });
 */
