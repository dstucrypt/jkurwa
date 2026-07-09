jkurwa examples
===============

Runnable, copy-pasteable snippets for the main use cases. Each file is
standalone and documented at the top.

Signing & verification, low level (ESM)
---------------------------------------

Working directly with `jk.models.Message`:

| File | What it shows |
|------|---------------|
| [`sign.js`](./sign.js) | Sign a document with DSTU 4145 + GOST 34.311 and write a CMS `signedData` file (and the tax-office transport envelope). |
| [`verify.js`](./verify.js) | Parse a signed message and verify its signature. |
| [`kupyna.js`](./kupyna.js) | Hashing with Kupyna (DSTU 7564:2014) and signing a message whose digest OID is Kupyna instead of GOST 34.311. |

High-level API (jk.Box)
-----------------------

`Box` ties keys, certificates, CA lists and the `algo` together; `pipe()` runs
outbound operations and `unwrap()` handles inbound messages.

| File | What it shows |
|------|---------------|
| [`box-sign.js`](./box-sign.js) | Sign via `box.pipe([{ op: "sign" }])` (plus transport envelope and forced-hash notes). |
| [`box-verify.js`](./box-verify.js) | Verify/receive via `box.unwrap()`. |
| [`box-encrypt.js`](./box-encrypt.js) | Encrypt to a recipient certificate and decrypt it back. |

Encryption, containers & PKI
----------------------------

| File | What it shows |
|------|---------------|
| [`gost-crypt.js`](./gost-crypt.js) | Encrypt data with DSTU 4145 key agreement + GOST 28147 block cipher. |
| [`gost-decrypt.js`](./gost-decrypt.js) | Decrypt the message produced by `gost-crypt.js`. |
| [`decrypt.js`](./decrypt.js) | Decrypt a CMS `envelopedData` message. |
| [`unpack.js`](./unpack.js) | Read private keys out of a `Key-6.dat` container. |
| [`certfetch.js`](./certfetch.js) | Fetch certificates over CMP. |
| [`ocsp.js`](./ocsp.js) | Build and send an OCSP request. |
| [`tsp.js`](./tsp.js) | Build a TSP (timestamp) request. |

Notes
-----

* The `sign.js` / `verify.js` / `kupyna.js` examples read test material from
  [`../test/data`](../test/data) via `import.meta.url`, so they run from any
  working directory.
* jkurwa's `main` is the bundled `dist/index.js`; the library sources under
  `lib/` use extensionless imports, so run these through your bundler/app (or
  `npm run build` and import from `../dist/index.js`) — they are written to be
  faithful, copy-pasteable references.
