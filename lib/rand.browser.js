/*
 * Cryptographically secure random-byte source (browser implementation).
 *
 * The package.json `browser` field selects this module in place of rand.js when
 * bundling for browsers; it relies on the Web Crypto API exposed as
 * `globalThis.crypto` rather than Node's `crypto` module.
 */
/**
 * Fill the given typed array with random bytes via Web Crypto.
 * @param {Uint8Array} fill Buffer to fill in place.
 * @returns {Uint8Array} The same buffer, now filled with random bytes.
 */
export default function (fill) {
  return globalThis.crypto.getRandomValues(fill);
}
