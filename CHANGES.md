# Changelog

Commit-by-commit history of notable changes, newest first. Commit hashes match
`git log`; older entries are omitted for brevity — run `git log` for the full
history.

## 2026-07-10

- **c0f7f08** — chore: modernize eslint/prettier, add lint script and CI step
- **f6510d2** — style: reformat with prettier 3 (whitespace only)
- **16d1996** — fix: make the library loadable by plain Node ESM, fix strict-mode crashes
  - Adds explicit `.js` extensions to all relative imports, so `lib/` and the
    examples run with plain `node` (previously only vite/esbuild could resolve them).
  - Fixes assignments to undeclared identifiers that threw `ReferenceError` in
    strict mode (`lib/util.js`, `OcspResponse.js`, `cmp.js`, `packed_xml.js`,
    `Priv.js`); converts `examples/gost-*.js` from `require()` to ESM.
- **ade69ba** — chore: fix npm packaging metadata and publish flow
- **a7d15d7** — chore(ci): replace Travis CI with GitHub Actions, drop codecov
- **cc91b19** — chore(deps): pin asn1.js to a commit, tighten bn.js and buffer ranges
- **0c96933** — fix(deps): npm audit fix — patch a critical vitest advisory (dev dependency)
- **0463fd7** — docs: rewrite README, add Ukrainian translation and runnable examples
- **feca770** — feat: Kupyna (DSTU 7564:2014) hash support
  - Kupyna-256/384/512 alongside GOST 34.311; the hash is auto-selected from the
    signing certificate and from a message's `digestAlgorithm`, or forced via
    `new Box({ hashMethod })` / `sign(..., { hash })` (`Box.EHASH` on unknown value).
  - Registers the DSTU 7564 OIDs; adds `@li0ard/kupyna` as a dependency.
- **e22f838** — chore: regenerate package-lock to prune stale jest/babel packages

## 2026-07-09

- **ab5b1f8** — fix: make test fixtures line-ending safe and PBES2 store parse robust
  - Adds `.gitattributes` (PEM → LF, DER/PKCS#7 → binary) so `core.autocrlf`
    no longer corrupts fixtures on Windows checkouts.
  - `Priv.from_protected` no longer lets a later parser clobber an earlier
    successful result, fixing PBES2 key loading.

## 2026-05-12

- **43dbf34** — use offsets without -8 for parser
- **a4c2a4c** — try loading pfx from different offsets

## 2026-05-08

- **0e20017** — add pb 191 to standard curves

## 2026-05-07

- **8033a1e** — fix a bug in PB_191 base point expansion

## 2025-08-25

- **624dd60** — added another link to readme
