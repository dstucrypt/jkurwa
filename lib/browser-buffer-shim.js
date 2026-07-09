/*
 * esbuild --inject target for browser bundles.
 *
 * gost89 (and a couple of transitively bundled CommonJS modules) reach for
 * `Buffer` as an ambient global — the way it exists in Node. Pull the
 * userland `buffer` polyfill in explicitly and expose it on globalThis so
 * those bare references resolve.
 */
import { Buffer } from "buffer";

if (!globalThis.Buffer) {
  globalThis.Buffer = Buffer;
}
