/*
 * Adapter that exposes the DSTU 7564:2014 (Kupyna) hash function from
 * `@li0ard/kupyna` with the same shape as `gost89.compat.algos().hash`:
 * a `(buffer) => Buffer` function tagged with an `.algo` property that holds
 * the OID name used by the ASN.1 layer (see lib/spec/rfc3280.js).
 *
 * `@li0ard/kupyna` is a regular dependency and Kupyna is always available: the
 * Box seeds these hashes into its lookup automatically (see lib/util/hashes.js),
 * so GOST- and Kupyna-signed material is handled with no extra configuration.
 */
import { Buffer } from "buffer";
import { kupyna256, kupyna384, kupyna512 } from "@li0ard/kupyna";

function tag(fn, algo) {
  const hash = data => Buffer.from(fn(Uint8Array.from(data)));
  hash.algo = algo;
  return hash;
}

const hash256 = tag(kupyna256, "Dstu7564-256");
const hash384 = tag(kupyna384, "Dstu7564-384");
const hash512 = tag(kupyna512, "Dstu7564-512");

const BY_BITS = { 256: hash256, 384: hash384, 512: hash512 };

/**
 * Mirror of `gost89.compat.algos()` for Kupyna. Returns an object with a `hash`
 * function (Kupyna-256 by default) that can be dropped into `algo.hash`.
 *
 *   const algo = { ...gost89.compat.algos(), hash: kupyna.algos().hash };
 */
function algos(bits = 256) {
  const hash = BY_BITS[bits];
  if (!hash) {
    throw new Error(`Unsupported Kupyna size: ${bits} (expected 256, 384 or 512)`);
  }
  return { hash };
}

export { algos, hash256, hash384, hash512 };
export default { algos, hash256, hash384, hash512 };
