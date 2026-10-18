# Kupyna / Kalyna port onto `master`

This document accompanies `docs/kupyna-kalyna-port.diff` — one aggregated diff
that takes the Kupyna/Kalyna work from `stable` and lands it on the modern
`master` line.  Every change site is annotated with why it exists, what it
touches, and how it is covered by a test.

The port is **change-site by change-site**, not a merge.  `stable` is a
1.21.12 CommonJS/jest tree; `master` is 1.22.9 ESM/tsdown/vitest and has already
absorbed the PB_191 curve arithmetic.  Merging the two lines would bury this
~500-line, 20-file delta under ~18k lines of formatting churn.

---

## 1. What "Kupyna/Kalyna support" actually means here

Three independent pieces of DSTU cryptography enter through three different
doors:

| Piece | Standard | Where it enters |
| --- | --- | --- |
| Message digest | DSTU 7564:2014 (Kupyna) | `Message` digest selection, `Certificate` chain verification, TSP imprint |
| Signature flavour | DSTU 4145 + Kupyna | `Dstu4145leWithDstu7564` signature OID and the `*_KU` curve OIDs |
| Container cipher | DSTU 7624:2014 (Kalyna) | PBES2 password-based key containers (`Dstu7624cbc-256`) |

The unifying design is a **name-keyed hash map**.  Before this port a `Box`
carried exactly one hash function and every layer hard-coded `Gost34311` and
`Dstu4145le` when it wrote an algorithm identifier.  After the port:

- `Box` owns `algo.hashes = { "Gost34311": fn, "Dstu7564-256": fn, ... }`.
- `Box.getHashAlgo(name)` returns a callable tagged with `.algo = name`.
- `Message` reads the digest name back out of its own `SignedData` and uses it
  for signing, verification, the signing-certificate attribute and timestamps.
- `Certificate` verifies with `hashes[certificate.signatureAlgorithm]`.

A Kupyna-capable `Box` therefore needs four keys in the map — the digest itself,
the Kupyna signature OID, and the two GOST names used by the older certificates
that usually sit in the same chain:

```js
const box = new jk.Box({
  algo: {
    hash: kupynaHash,
    hashes: {
      "Dstu7564-256": kupynaHash,
      Dstu4145leWithDstu7564: kupynaHash,
      Gost34311: gostHash,
      Dstu4145le: gostHash
    }
  }
});
```

That last point is the subtle one: a certificate's `subjectKeyIdentifier` is
computed with the **certificate's own** signature hash.  Probing a Kupyna
certificate with the GOST function produces a different key id and rejects an
otherwise valid chain.

---

## 2. Annotated change sites

### `lib/spec/rfc3280.js` — algorithm OIDs

Adds the DSTU 7564 family (`Dstu7564`, `-256`, `-384`, `-512`,
`Dstu7564mac-256/384/512`), the DSTU 7624 CBC family (`-128`, `-256`, `-512`)
and `Dstu4145leWithDstu7564`.

**Why:** `asn1.js` resolves `OBJECT IDENTIFIER` through this table.  Without an
entry the parser either fails or leaves a numeric string that no downstream
`switch` understands.  These names are also the exact keys later looked up in
`hashes[...]`, so a typo here becomes a silent "no hash implementation" error.
The MAC OIDs matter because Kupyna key containers use
`PBKDF2-HMAC(Dstu7564mac-256)`.

### `lib/standard.js` — `_KU` curve aliases

Adds `DSTU_PB_191_KU`, `DSTU_PB_257_KU`, `DSTU_PB_431_KU`, aliased to the
existing parameter objects.

**Why:** `Curve.from_id(name)` does `standard[name]`, and `keystore.js` now maps
the Kupyna curve OIDs to `*_KU` names.  DSTU 4145 over Kupyna uses identical
curve parameters; only the accompanying hash OID differs.

**Known limitation (see checklist):** only the curves whose parameters are
present in `standard.js` (191/257/431) get an alias.  The other seven KU OIDs
resolve to names that `from_id()` will reject.  This is pre-existing behaviour,
but the port makes it reachable.

### `lib/spec/keystore.js` — Kupyna curve OIDs

Adds the ten OIDs under `1.2.804.2.1.1.1.1.3.6.1.1.2.N` as `DSTU_PB_*_KU`.
Note the space-separated spelling: `master` keys its `objid()` tables that way,
while the old branch used dots.

**Why:** Kupyna-flavoured key containers encode the curve with this arc.  An
unmapped OID makes `guessStore`/`enc_parse` fail with a generic parse error.

### `lib/spec/dstszi2010.js` — Kalyna CBC parameters

Defines `DSTU7624CBCParameters` (a single 32-byte `iv`) and registers it as
`Dstu7624cbc-256` in `ContentInfo.algoModel`.

**Why:** PBES2's DSTU profile wraps a Kalyna-CBC payload, whose parameters are
just an IV — there is no DKE s-box as in the GOST profile.  Without the model
the `parameters` field cannot be decoded.

**Limitation:** only the 256-bit variant is registered, because only
`Dstu7624cbc-256` is handled by the PBES2 dispatcher.

### `lib/spec/pbes.js` — PBES2 profile dispatch

`pbes2_parse_asn1` previously assumed one profile:
`PBKDF2-HMAC(Gost34311) + Gost28147-CFB`, with an 8-byte IV and a 64-byte DKE
s-box.  It now dispatches on the **PBKDF2 PRF**, via a `PBES2_PROFILES` table:

- `Gost34311-hmac` → `Gost28147-cfb`, IV 8, DKE 64;
- `Dstu7564mac-256` → `Dstu7624cbc-256`, IV 32, no DKE.

The KDF/cipher pair is validated together.  The returned store now carries
`kdf` and `enc` names so that a custom `algo.storeload` (dstucrypt-algos) can
dispatch without re-parsing the container.

**Not changed:** `pbes2_serialize` still writes only the GOST profile.  Writing
Kupyna containers is out of scope for this port and is called out in the
checklist.

### `lib/spec/rfc5035-certid.js` — signing-certificate digest name

`SigningCertificateV2.wrap(cert, hash, hashName)` now records `hashName` as
`ESSCertIDv2.hashAlgorithm.algorithm`.  The default remains `Gost34311` for
callers that have not been updated.

**Why:** a verifier recomputes the certificate digest with the algorithm named
in the attribute.  Recording GOST while the value was produced by Kupyna makes
the attribute fail — or worse, makes it verify under a different algorithm than
the one the signer intended.

### `lib/models/Message.js` — digest dispatch through the whole message

This is the largest change site.

- `SIGNATURE_ALGOS` maps each digest name to its signature OID:
  `Gost34311 → Dstu4145le`, `Dstu7564-{256,384,512} → Dstu4145leWithDstu7564`.
- `constructSigned()` resolves `hashAlgo` once (`ob.hash.algo`, with
  `Gost34311` as the legacy default) and derives `sigAlgo`.  An unknown digest
  now throws instead of silently emitting `digestEncryptionAlgorithm:
  undefined`.
- `digestAlgorithms`, `digestAlgorithm` and `digestEncryptionAlgorithm` are
  written from those two values.
- `signingCertificateV2` receives `hashName`.
- `addSignature(hashes, signer)`, `mhash(hashes)`, `verifyAttrs(hashes, …)`,
  `verifyAttrDigest(dgst, hashes)`, `verifyTimestampToken(msg, hashes, …)` and
  `verify(hashes, …)` take the name-keyed map.
- `mhash` reads the digest algorithm back out of `this.info.digestAlgorithms`
  rather than accepting it as an argument, so signing and verification cannot
  disagree.
- `digestAlgorithmOf()` and `hashFnFor()` are named helpers; a missing
  implementation is an explicit error, not a null signature.
- Timestamp tokens may legitimately use a different digest than the message
  they stamp.  The token's claimed imprint algorithm is resolved by name and an
  unknown one causes rejection (untrusted input, so `false`, not `throw`).

### `lib/models/Certificate.js` — key id uses the certificate's own hash

Both `verify()` and `verifySelfSigned()` now compute
`keyid({ hash: hashes[this.signatureAlgorithm] })`.

**Why:** the `subjectKeyIdentifier` extension is defined in terms of the
certificate's signature algorithm.  Hard-coding `Dstu4145le` breaks every
Kupyna-signed certificate in the chain.

### `lib/models/OcspResponse.js` — OCSP responder verification

`responder.verify(..., ctx.hashes, ...)` instead of
`{ Dstu4145le: ctx.hashFn }`.

**Why:** an OCSP responder may be certified under either hash family; the
certificate's own algorithm decides, and that only works when the full map is
passed.

### `lib/services/tsp.js` — timestamp requests name their digest

`getStamp(cert, hashedMessage, hashAlgoName, query)` writes `hashAlgoName` into
`TimeStampReq.messageImprint.hashAlgorithm`.

**Why:** a TSA signs the digest it is handed; a request that labels a Kupyna
digest as `Gost34311` produces a token that cannot be verified against the
content.  `hashAlgoName` is required — the only two callers are inside `Box`,
which always has a name.

### `lib/app/ctx.js` — the Box owns the algorithm table

- Constructor: `defaultHash` (default `Gost34311`), plus promotion of the
  legacy single `algo.hash` into `algo.hashes`.
- `getHashAlgo(name)` resolves and tags a callable; unknown names throw.
- `ocspCtx` carries both `hashFn` and the full `hashes` map.
- `verifyCert()` passes `this.algo.hashes`.
- `sign()` uses `getHashAlgo(opts.hash)` for the data hash, the signature hash
  and the `Message`; TSP calls receive `opts.hash`.
- `CertificateRef.fromCert()` now receives `getHashAlgo(opts.hash)`; the old
  `this.algo.hash` was `undefined` for callers that supplied only a map.
- `unwrap()` passes `this.algo.hashes` into `Message.verify`.

**Deliberate deviation from `stable`:** the "hash defaults to Gost34311" warning
was dropped.  It fired on every `Box` construction, including Kupyna boxes, and
was noise rather than a migration signal.  The single-`algo.hash` deprecation
warning is kept and fires once per Box.

### `test/` — the tests that make the port meaningful

| File | What it proves |
| --- | --- |
| `test/test-czo-kupyna.js` | CAdES-BES signed with Kupyna: unwrap, signature, and full chain verification against the CZO test root |
| `test/test-czo-kupyna-t.js` | Same for CAdES-T (timestamped Kupyna signature) |
| `test/test-kupyna-specs.js` | PBES2 GOST and Kalyna profiles, mismatched/unknown rejection, IV-length rejection, `SigningCertificateV2` digest name, Box algorithm-table construction, KU curve aliases |
| `test/utils.js` | `kupynaHash()` / `kupynaBox()` helpers |
| `test/test-sign.js` | updated to pass the algorithm map into `verify` / `verifyAttrs` (behaviour unchanged) |

`dstu7564@^1.1.1` is added as a **devDependency**.  The old branch's Kupyna
tests imported it without declaring it, so they could never have run in CI.

Test data added: `test/data/test-kupyna-czo.p7s`, `test/data/test-t-kupyna.p7s`.

---

## 3. How to test

```sh
bun install
bunx vitest run --testTimeout=300000
```

The machine this was ported on is a riscv64 box; BigInt-heavy verification is
slow (a Kupyna chain verification is ~110 s, a GOST one ~17 s per case).
Vitest's default 5 s timeout is therefore too small — pass `--testTimeout`.
The `[vitest-worker]: Timeout calling "onTaskUpdate"` lines are a harness
artifact of the slow worker, not test failures.

Targeted runs:

```sh
bunx vitest run test/test-kupyna-specs.js          # fast, pure ASN.1
bunx vitest run test/test-sign.js                  # GOST signing regression
bunx vitest run test/test-czo-gost.js              # GOST CAdES-BES regression
bunx vitest run test/test-czo-kupyna.js test/test-czo-kupyna-t.js
```

Build check:

```sh
bun run build
```

---

## 4. Pre-release checklist

### Must pass

- [ ] `bunx vitest run --testTimeout=300000` — all files green (ignore the
      `onTaskUpdate` worker warnings).
- [ ] `test/test-czo-kupyna.js` — Kupyna CAdES-BES unwraps, signature valid,
      chain verified against the CZO test root.
- [ ] `test/test-czo-kupyna-t.js` — Kupyna CAdES-T same.
- [ ] `test/test-czo-gost.js`, `test-czo-t.js`, `test-czo-x.js` — GOST
      containers unchanged.
- [ ] `test/test-sign.js` — 15/15, including the tax-office transport fixtures.
- [ ] `test/test-kupyna-specs.js` — 11/11.
- [ ] `bun run build` — tsdown emits `dist/index.cjs` and `dist/index.mjs`.
      **Blocked on the riscv64 host this port was written on:** tsdown's
      rolldown has no `linux-riscv64` native binding (`@rolldown/binding-linux-riscv64-gnu`
      resolves to a placeholder 0.0.0).  The library itself imports and the full
      vitest suite runs; run the build on x86_64/arm64 CI before publishing.

### Behaviour to confirm by hand

- [ ] A `Box` constructed with **only** `algo.hashes` (no `algo.hash`) can
      unwrap and sign.  (The old `CertificateRef.fromCert(cert,
      this.algo.hash)` path would have crashed here.)
- [ ] A `Box` constructed with the legacy `algo.hash` still signs and verifies.
- [ ] `Box.sign(..., { hash: "Dstu7564-256" })` produces a `SignedData` whose
      `digestAlgorithms`, `digestAlgorithm`, `digestEncryptionAlgorithm` and
      `signingCertificateV2.hashAlgorithm` all name Kupyna consistently.
- [ ] A Kupyna-protected key container parses through `Priv.from_protected`
      and its store exposes `kdf: "Dstu7564mac-256"`, `enc: "Dstu7624cbc-256"`
      and a 32-byte IV.

### Known limitations — either accept or file

- [ ] **PBES2 writing is GOST-only.** `pbes2_serialize` cannot emit a Kalyna
      container.  Reading Kupyna containers works; creating them does not.
- [ ] **Only `Dstu7624cbc-256` is dispatched.**  `-128` and `-512` OIDs exist in
      `rfc3280.js` but have no parameter model and no parser branch.
- [ ] **Seven KU curve OIDs have no parameters.**  `DSTU_PB_163_KU` …
      `DSTU_PB_367_KU` (except 191/257/431) resolve in `keystore.js` but throw in
      `Curve.from_id`.  Decide whether to bundle the remaining curves or to
      remove the OIDs.
- [ ] **Certificate issuance is still GOST-only.** `Certificate.signCert()` stamps
      `privkey.algorithm` (`Dstu4145le`) and `privkey.curve.name()` (the non-KU
      curve name).  Parsing, verifying and chain-building Kupyna certificates
      works; *creating* them does not.  Keep this out of the release notes as a
      feature claim.
- [ ] **Kupyna CAdES fixtures come from `stable`.**  They are binary test data,
      not regenerated by this port; confirm they are the intended fixtures
      before publishing.

### Release mechanics

- [ ] `package.json` version bumped to **1.23.0**.
- [ ] `CHANGES.md` entry describing the Kupyna/Kalyna support.
- [ ] `package.json` `exports`/`main`/`module` unchanged (`dist/` paths).
- [ ] `npm pack --dry-run` includes `lib/`, `dist/`, and excludes `docs/`.
- [ ] `git diff master...kupyna-port --stat` reviewed once end-to-end.
- [ ] Push `kupyna-port` to `master` (fast-forward or merge commit, per
      repository convention).

---

## 5. Things deliberately not ported from `stable`

- The m=191 / PB_191 arithmetic fixes: **already present on `master`**
  (`DSTU_PB_191`, `truncateTo`, `inv_slow`, `pad_scalar`).  Verified by
  `git merge-base --is-ancestor 318a6ed master`.
- `parseWithFn` / `enc_parse_many`: already present on `master`.
- Formatting and CommonJS syntax: this port keeps `master`'s ESM and Prettier
  style.
