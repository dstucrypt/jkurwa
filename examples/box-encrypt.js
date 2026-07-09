/*
 * High-level encryption and decryption with jk.Box.
 *
 *   node examples/box-encrypt.js
 *
 * The sender encrypts to a recipient certificate; the recipient decrypts with
 * their private key. Encryption needs the sender's own key pair (for the
 * ephemeral DSTU 4145 key agreement) plus the recipient's certificate.
 */
import fs from "fs";
import gost89 from "gost89";
import * as jk from "../lib/index.js";

const asset = name => new URL(`../test/data/${name}`, import.meta.url);
const algo = gost89.compat.algos();

const senderPriv = jk.Priv.from_asn1(fs.readFileSync(asset("Key6929.cer")));
const senderCert = jk.Certificate.from_asn1(fs.readFileSync(asset("SELF_SIGNED_ENC_6929.cer")));
const recipientPriv = jk.Priv.from_asn1(fs.readFileSync(asset("Key40A0.cer")));
const recipientCert = jk.Certificate.from_asn1(fs.readFileSync(asset("SELF_SIGNED_ENC_40A0.cer")));

// --- sender ---
const sender = new jk.Box({ algo });
sender.load({ priv: senderPriv, cert: senderCert });
const encrypted = await sender.pipe(
  Buffer.from("secret message"),
  [{ op: "encrypt", forCert: recipientCert }]
);
fs.writeFileSync("box-encrypted.p7", encrypted);
console.log(`wrote box-encrypted.p7 (${encrypted.length} bytes)`);

// --- recipient ---
// Decryption needs the recipient's own key pair AND the sender's certificate:
// the DSTU 4145 shared key is derived from the recipient's private key and the
// sender's public key. Without the sender cert unwrap() throws ENOCERT.
const recipient = new jk.Box({ algo });
recipient.load({ priv: recipientPriv, cert: recipientCert });
recipient.load({ cert: senderCert });
const { content, error } = await recipient.unwrap(encrypted);
console.log("decrypt error:", error);
console.log("decrypted:    ", content && content.toString());
