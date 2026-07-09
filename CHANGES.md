# Changelog

**English** · [Українська](./CHANGES.uk.md)

Notable changes, newest first, grouped by the commit that introduced them
(hashes match `git log`). Trivial and style-only commits are omitted — run
`git log` for the complete history.

## 2026-07-10

### Kupyna signer OID fix

- `Message.constructSigned` used to hard-code the legacy `Dstu4145le` OID as
  the `digestEncryptionAlgorithm` of every signerInfo, even when the message
  was hashed with Kupyna. Ukrainian verifiers rejected the mismatch as
  "Невірний підпис(35)". The OID is now paired with the digest via
  `SIG_FOR_HASH`, always picking the `-pb` variant
  (`Dstu4145le-Dstu7564-256/384/512-pb`) because jkurwa only supports
  polynomial-basis curves.

### Documentation, types & security

- Documented the entire `lib/` with English JSDoc and inline comments — module
  headers, per-export API docs, and notes on the GF(2ᵐ) math, ASN.1 schemas and
  DSTU/GOST specifics (comments only; behaviour unchanged).
- Hand-written TypeScript declarations for the public API — b049617.
- Added `SECURITY.md` and documented the spec-coverage limitations explicitly —
  e67df4b, b687983.
- Added official DSTU 7564 test vectors for Kupyna-384 and Kupyna-512 — 6fea8a1.

### Kupyna (DSTU 7564:2014) hash support — feca770

- New `lib/util/kupyna.js` adapter over `@li0ard/kupyna`, exposing Kupyna-256 /
  384 / 512 each tagged with its DSTU 7564 OID name.
- New `lib/util/hashes.js` selection engine: builds by-digest and
  by-signature-algorithm lookup maps and keeps the `subjectKeyIdentifier` hash
  on GOST 34.311.
- `Box` picks the hash automatically — from the signing certificate
  (`hashForCert`) when signing and from a message's `digestAlgorithm`
  (`hashForMessage`) when verifying. Override it with `new Box({ hashMethod })`
  or per call via `sign(..., { hash })`; an unknown value throws `Box.EHASH`.
- `Message` carries the chosen digest OID into the CMS and gains a `digestAlgo`
  getter; TSP requests, `SigningCertificateV2` and OCSP responses honour it too.
- Registered the DSTU 7564 hash OIDs and the DSTU 4145-with-Kupyna signature
  OIDs in `lib/spec/rfc3280.js`.
- Added `@li0ard/kupyna` as a dependency and a dedicated test suite
  (`test/test-kupyna.js`).

### Plain-Node ESM loading & strict-mode fixes — 16d1996

- Added explicit `.js` extensions to every relative import in `lib/`, so the
  sources load under plain `node` (previously only vite/esbuild could resolve
  them).
- Fixed assignments to undeclared identifiers that threw `ReferenceError` in
  strict mode (`lib/util.js`, `models/OcspResponse.js`, `services/cmp.js`,
  `util/packed_xml.js`, `models/Priv.js`, `app/keycoder.js`, `point.js`).
- Converted `examples/gost-crypt.js` and `gost-decrypt.js` from `require()` to
  ESM.

### Documentation & examples — 0463fd7

- Rewrote the README (English) and added a Ukrainian translation
  (`README.uk.md`) with a language switcher.
- Added runnable examples: `sign` / `verify` / `kupyna` (low-level `Message`)
  and `box-sign` / `box-verify` / `box-encrypt` (high-level `Box`), plus an
  `examples/README.md` index.

### Tooling, CI & dependencies

- Modernised eslint/prettier, added a lint script and a CI lint step — c0f7f08.
- Fixed npm packaging metadata and the publish flow — ade69ba.
- Replaced Travis CI with GitHub Actions and dropped codecov — a7d15d7.
- Pinned `asn1.js` to a commit and tightened `bn.js` / `buffer` ranges —
  cc91b19.
- Patched a critical `vitest` advisory via `npm audit fix` (dev dependency) —
  0c96933.
- Regenerated the lockfile to prune stale jest/babel packages — e22f838.

## 2026-07-09

### Line-ending-safe fixtures & robust store parsing — ab5b1f8

- Added `.gitattributes` (PEM → LF, DER/PKCS#7 → binary) so `core.autocrlf` no
  longer corrupts the byte-exact test fixtures on Windows checkouts.
- `lib/util/pem.js` `from_pem` strips CR before base64 decoding, tolerating CRLF
  PEM input.
- `Priv.from_protected` no longer lets a later parser clobber an earlier
  successful result, fixing PBES2 key loading.

## 2026-05

### DSTU 4145 curves & containers

- Added the PB_191 standard curve — 0e20017.
- Fixed the PB_191 base point expansion — 8033a1e.
- Load PFX / PKCS#12 containers from alternate byte offsets — a4c2a4c, 43dbf34.

## 2025-06

### ES modules & build tooling

- Rewrote the whole codebase from CommonJS to ES modules — 541f5ed, da13693.
- Added an esbuild bundler and stopped inlining `node_modules` dependencies;
  relative imports dropped their file extensions (later restored for plain Node,
  see 16d1996) — 3d4ef75, 0a0e05b, acc73d2.
- Migrated the test runner from jest to vitest and split the unit tests —
  ea3b21b, 5065f65.
- Initialised `Box` keys with an empty list so tests fail less noisily —
  472ba01.

## 2024

- Ignore opaque bags carrying an IIT identifier when reading key containers —
  6d567d6.

## 2023

- Index private keys by key id separately from certificates — 588e709.
- Cast the password to a string when opening JKS containers — 6c176db.
- Fixed the certificate key-usage bits parser — d7d5f2d.
- Routine dependency bumps (dependabot).

## 2022

- Extended `jk.Box` with certificate-fetch (CMP) functionality — 43cf3b3.
- Read the certificate out of a PFX bag when it is present — ee0afec.
- Read PFX with PBES2-style params (Oschadbank) and fixed loading of certain PFX
  files — ae0f047, c59d0ed.
- Support OCSP reference by key id in responses — da43ef3.
- `jk.guess_parse` now returns a list of stores when several are found —
  5951184.
- Added the "corporate" signer role (director | other) — b2cfedc.
- Made `dke` optional in encryption params; fixed the cofactor for the PB_430
  curve — ecc7ced, 0c28f5a.

## 2021

- Load an additional private-key store format — 96fd5f9.

## 2020

### Certificate validation, CA & OCSP

- Load and index a CA list and verify certificate signatures recursively up the
  chain — 6c4c68d, e39d34b, b606e26.
- Verify certificate key usage and reject certificates whose role does not match
  — 18c5aaf, ceaa15a.
- OCSP checks: strict by default, opportunistic responder discovery,
  verification of stored responses, and enforcement that the responder shares
  the certificate's CA — bc5830c, 9f5c28a, d706b39, ddf2740.
- Cache certificate-verification results and keep separate CA and certificate
  RDN indexes — abfb2a8, 5a306c5.
- Option to restrict the library to standard curves only — ea3fca0.

### Timestamps (TSP) & message chain

- Unpack and verify TSP stamps, with content and signature timestamps toggled
  separately — 4b2cc2e, 0a87b20.
- Add OCSP stamps to messages and write certificate references / the full chain
  on request — f6893b2, 3b3c3cd.

### Keys & refactoring

- Added `to_pbes2()` on private keys and reading of PBES2 keys without
  attributes (one key per file) — 2c0db7d, b99c708.
- Refactored the Message and Certificate models and split out the loader and the
  role filter — 4da45d2, 7320be3, cf69bc0, 4cccdfd.

## 2019

### High-level Box API

- Built the `Box` workflow: sign and verify through the box interface,
  encrypt/decrypt over DH, `unwrap()`, clear-data and encrypted-transport
  containers, and detached signatures — 99704eb, ce91a74, b1d0f9d, 33d2520.
- **API change:** `box.pipe()` now returns a promise — a3ff3bb.

### Keys, certificates & curves

- Added key encryption and serialisation in PBES2 format (v1.1.0) — 03c2062.
- Verify and construct a self-signed root; verify messages signed by a
  self-signed certificate — 968e438, 54a24a5.
- Rewrote `curve.js` and the point class with ES6 classes and converted
  `Certificate` to an ES6 class — 804970e, 155eb02, b7c163f.
- Fixed a dormant performance bug in the wNAF point multiplier — 23d94f1.

## 2018

- Parse a message from ASN.1 — 691d13f.
- Added TSP (timestamp) support, at the cost of making `Box.pipe()` async —
  2e02866.
- Parse ECDSA certificates (parsing only, no full support yet) — 920e2fb.
- Conform to the PBKDF2 schema (added the key-size field) — 148019d.

## 2017

- Save the TSP token into the CMS message — 03cb60a.
- Lazy certificate parsing — 296d667.
- Use `msCrypto` when running in IE11 — f40ab5d.
- Load keystores with standard curves; wrap a bag with PBES inside — 447d1a2,
  2caaf0f.

## 2016

- Byte-to-byte compatibility with the tax report server — 9ddcccf.

## 2015

- Unpack MeDoc's `PACKED_XML` documents; split `js-lzma` into its own package —
  7740176, 032b5b7.
- USC/QLB transport support and `ZPOSTTRANSPORTABLE` parsing — d417bd7, 1276613,
  9021149.
- Support named curves — 7a81458.
- Added OCSP schemas and example code — 68ddcaa.
- Parse and verify signing time, verify PKCS#7 attributes and detached
  signatures; fixed message encryption/decryption and the key loader — 85b0161,
  a88e88b, e7420f9, 863e751.

## 2014 — initial implementation

- GF(2ᵐ) elliptic-curve arithmetic and DSTU 4145 signing — point add/multiply,
  signing with a private key, PRNG from sjcl — 6644f5f, 68cc429, f52e9d0.
- DSTU 4145 signatures with the "short" ASN.1 wire format — e45cdba, a38c042,
  4dfc6a2.
- PKCS#7 / CMS: ASN.1 schemas (`ContentInfo`, `SignerInfo`), message decryption,
  the transport encoder, and ephemeral keys — 411857b, 950c7b0, 7f15eaa,
  0c30f61.
- Certificates: parse the public key from a certificate, load an X.509
  certificate, export certificate data as a dict — ed84bef, 50f2d02, 1403ad3.
- Standard curve PB_431, keystore definitions, and the initial (incomplete)
  CMP/CRMF schemas — 791bb99, cd663b5, 8cb24d1.
