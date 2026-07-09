/*
 * Cryptographically secure random-byte source (Node.js implementation).
 *
 * The package.json `browser` field swaps this module for rand.browser.js when
 * bundling for browsers; that variant uses the Web Crypto API instead of Node's
 * `crypto` module.
 */
// This file should be used on node
// Bundler should replace it with
// rand.browser.js for browsers
import crypto from "node:crypto";
/**
 * Fill the given buffer with random bytes.
 * @param {Uint8Array|Buffer} xb Buffer to fill in place.
 * @returns {Buffer} The freshly generated random bytes.
 */
export default function (xb) {
  const ret = crypto.rng(xb.length);
  for (let i = 0; i < xb.length; i++) {
    xb[i] = ret[i];
  }
  return ret;
}
