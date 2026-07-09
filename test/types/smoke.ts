/*
 * Type-level smoke test: compiled by `npm run typecheck` (tsc --noEmit),
 * never executed. Exercises the public API surface declared in
 * types/index.d.ts the way README examples use it.
 */
import { Buffer } from "buffer";
import * as jk from "jkurwa";
import Box from "jkurwa";

declare const algo: jk.Algo;
declare const keyBuffer: Buffer;
declare const data: Buffer;

// --- Box construction ------------------------------------------------------
const box = new Box({
  algo,
  keys: [{ keyBuffers: [keyBuffer], password: "secret" }],
  hashMethod: "kupyna"
});
new jk.Box({ algo, hashMethod: "auto", query: null });

// --- sign / pipe / unwrap --------------------------------------------------
async function flows(): Promise<void> {
  const message: jk.Message = await box.sign(data, "personal", null, {
    detached: true,
    tsp: "signature",
    includeChain: "ref",
    hash: "kupyna-512"
  });
  message.as_transport();

  const packed: Buffer = await box.pipe(data, [
    { op: "sign", tsp: true },
    { op: "encrypt", forCert: "-----BEGIN CERTIFICATE-----...", addCert: true }
  ]);

  const info: jk.UnwrapInfo = await box.unwrap(packed, undefined, { ocsp: "lax" });
  if (info.error === undefined && info.content) {
    info.content.toString("binary");
  }
  for (const step of info.pipe) {
    if ("signed" in step && step.signed === true && "cert" in step) {
      const subj: string = step.cert.subject.commonName;
      void subj;
    }
  }
}
void flows;

// --- low-level keys --------------------------------------------------------
const priv: jk.Priv = jk.pkey(
  "DSTU_PB_257",
  "40a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d"
);
const pub: jk.Pub = jk.pubkey(
  "DSTU_PB_257",
  "40ad1cb010531b504177577d8d4ad148219eb0c9bda61c9a0d4df1650d8cbe22"
);
const curve: jk.Curve = jk.std_curve("DSTU_PB_257");
void curve.keygen().pub();

const signature: Buffer = priv.sign(data, "short");
const split: jk.SplitSign = priv.sign(data);
const ok: boolean = pub.verify(data, signature, "short");
void [split, ok];

// --- certificates ----------------------------------------------------------
declare const certPem: string;
const cert: jk.Certificate = jk.Certificate.from_pem(certPem);
const dict: jk.CertDict = cert.as_dict();
void [dict.usage.sign, cert.canUseFor("sign"), cert.extension.ipn];

// --- loaders / transport / base64 -----------------------------------------
const material = jk.load({ certPem }, algo);
void material[0]?.cert;
jk.guess_parse(keyBuffer);

const envelope: Buffer = jk.transport.encode(
  [{ type: "UA1_SIGN", contents: data }],
  { EDRPOU: "12345678" }
);
const decoded = jk.transport.decode(envelope);
void decoded.docs[0]?.type;

const b64: string = jk.b64_encode(data, { line: 16, pad: true });
void jk.b64_decode(b64);

// --- errors ----------------------------------------------------------------
void (Box.EOLD === jk.EOLD);
try {
  /* noop */
} catch (e) {
  if (e instanceof jk.EHASH) {
    void e.message;
  }
}
