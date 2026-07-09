jkurwa
======

**English** · [Українська](./README.uk.md)

Ukrainian national cryptography (DSTU 4145) for JavaScript — elliptic curves
over GF(2ᵐ), digital signatures, encrypted containers and the PKCS#7/CMS
message formats used by the Ukrainian tax office and PRRO cash-register systems.

Pure JavaScript, runs in Node.js and the browser.

[![npm module](https://badge.fury.io/js/jkurwa.svg)](https://www.npmjs.org/package/jkurwa)
[![Build Status](https://travis-ci.org/dstucrypt/jkurwa.svg?branch=master)](https://travis-ci.org/dstucrypt/jkurwa)
[![codecov](https://codecov.io/gh/dstucrypt/jkurwa/branch/master/graph/badge.svg)](https://codecov.io/gh/dstucrypt/jkurwa)

![cej repo je strefa wolna wid Kaczyńskiego](https://raw.githubusercontent.com/muromec/jkurwa/master/kdpv.jpg)

What it does
------------

* **DSTU 4145 signatures** — sign and verify over short Weierstrass curves in the
  binary field GF(2ᵐ), with the standard named curves (e.g. `DSTU_PB_257`) or a
  custom curve.
* **Hash functions** — GOST 34.311-95 (via [gost89](https://github.com/dstucrypt/gost89))
  and **Kupyna / DSTU 7564:2014**, selected automatically from the signer's
  certificate or forced explicitly. See [Hash functions](#hash-functions).
* **Key containers** — reads and decrypts `Key-6.dat` (IIT proprietary), PBES2,
  PKCS#12 / PFX, and JKS containers (used by PrivatBank).
* **Signed & encrypted messages** — full read/write of the wicked PKCS#7 / CMS
  format used by the tax office (`sta.gov.ua`), including the `TRANSPORTABLE`
  transport envelope. See `jk.Box` and `jk.transport`.
* **Certificates & PKI** — parsers and builders for X.509 v3 certificates plus
  TSP (timestamp), CMP and OCSP requests and responses.
* **Encryption** — key agreement and GOST 28147 block-cipher wrapping for
  encrypted containers, when a cipher implementation (gost89) is supplied.

Install
-------

```sh
npm install jkurwa gost89
```

`gost89` provides the GOST block cipher, key wrapping and container loaders and
is passed in as the `algo` object. It is required for encryption, key-container
decryption and GOST hashing.

Quick start
-----------

### Sign and verify a hash (low level)

```js
import gost89 from "gost89";
import * as jk from "jkurwa";

const algo = gost89.compat.algos();

const priv = jk.pkey("DSTU_PB_257", "40a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d");
const pub = priv.pub();

const hash = algo.hash(Buffer.from("hello, world"));
const sign = priv.sign(hash, "le");

pub.verify(hash, sign, "le"); // => true
```

### Sign a document (high level)

The `Box` ties keys, certificates, CA lists and the hash/cipher `algo` together
and produces a complete CMS `signedData` message.

```js
import gost89 from "gost89";
import * as jk from "jkurwa";

const box = new jk.Box({ algo: gost89.compat.algos() });
box.load({ priv, cert }); // priv: jk.Priv, cert: jk.Certificate

const message = await box.sign(data, /* role */ null, null, { time });

// wrap into the tax-office transport envelope
const transport = message.as_transport({
  EDRPOU: "1234567891",
  RCV_EMAIL: "user@tax.mail.com",
  DOC_TYPE: "3",
});
```

### Read a private key from a container

```js
import fs from "fs";
import gost89 from "gost89";
import * as jk from "jkurwa";

const store = jk.Priv.from_protected(
  fs.readFileSync("Key-6.dat"),
  "PASSWORD",
  gost89.compat.algos()
);
store.keys.forEach((key) => console.log(key.as_pem()));
```

See the [`examples/`](./examples) and [`test/`](./test) directories for more,
and the [dstucrypt/agent](https://github.com/dstucrypt/agent) repo for a full app.

Hash functions
--------------

DSTU 4145 signatures are computed over a message digest, and jkurwa supports
both Ukrainian hash standards:

| Algorithm | OID | Notes |
|-----------|-----|-------|
| GOST 34.311-95 | `1.2.804.2.1.1.1.1.2.1` | legacy default, via `gost89` |
| Kupyna-256 (DSTU 7564:2014) | `1.2.804.2.1.1.1.1.2.2.1` | via [`@li0ard/kupyna`](https://www.npmjs.com/package/@li0ard/kupyna) |
| Kupyna-384 / Kupyna-512 | `…2.2.2` / `…2.2.3` | for 384/512-bit keys |

**Automatic selection.** With a plain `Box` the hash is chosen from the signing
certificate — a Kupyna certificate signs with Kupyna, a legacy GOST certificate
with GOST 34.311 — and an incoming message is verified with the hash named in
its `digestAlgorithm`. No configuration is needed:

```js
const box = new jk.Box({ algo: gost89.compat.algos() });
box.load({ priv, cert });
await box.sign(data, null, null, {}); // GOST key -> GOST, Kupyna key -> Kupyna
```

**Forcing a hash.** Set a default for the box, or override per call:

```js
new jk.Box({ algo, hashMethod: "kupyna" });       // default for every sign()
await box.sign(data, null, null, { hash: "gost" }); // override this one call
```

Accepted values are `"gost"`, `"kupyna"` (Kupyna-256), the size aliases
`"kupyna-384"` / `"kupyna-512"`, `"auto"` (the default), or your own tagged hash
function. An unknown value throws `jk.Box.EHASH`.

Supported formats
-----------------

* **Certificates** — X.509 v3 as profiled by DSTU (see the references below).
* **Private key containers** — `Key-6.dat` (IIT), PBES2, PKCS#12 / PFX, JKS.
* **Messages** — CMS `signedData` and `envelopedData`, the tax-office
  `TRANSPORTABLE` / `UA1_SIGN` transport envelopes.
* **PKI protocols** — OCSP, TSP (RFC 3161), CMP.

Security notes
--------------

* jkurwa does **not** guarantee constant-time computation.
* Signature verification checks the signature against a public key. It does
  **not** validate the X.509 certificate chain unless a CA list is loaded
  (`box.loadCAs(...)`). See the [dstucrypt/agent](https://github.com/dstucrypt/agent)
  readme for details.
* To cross-verify signatures independently, use <https://czo.gov.ua/verify>.

Sister libraries
----------------

* [ukurwa4145](https://github.com/dstucrypt/ukurwa4145) — DSTU 4145 in Python;
* [gost89](https://github.com/dstucrypt/gost89) — GOST cipher, hash, MAC, key
  wrapper and container loader in pure JS;
* [python-gost89](https://github.com/dstucrypt/python-gost89) — GOST hash for Python;
* [jksreader](https://github.com/dstucrypt/jksreader) — parser for the Java-style
  key containers used by PrivatBank;
* [zozol](https://github.com/muromec/zozol) — ASN.1 parser/serialiser for Python
  with X.509 and wicked CMS schemas;
* [openssl-dstu](https://github.com/dstucrypt/openssl-dstu) — patched OpenSSL with
  DSTU 4145 and GOST support (outdated, unmaintained).

Demo & apps
-----------

* <https://dstucrypt.github.io/signerbox2/> — in-browser demo;
* [dstucrypt/agent](https://github.com/dstucrypt/agent) — command-line utility and
  daemon to sign, encrypt and decrypt files;
* [dstukeys](https://github.com/dstucrypt/dstukeys) — web authentication examples;
* [e-rro](https://github.com/max1gu/e-rro) and
  [OpenPRRO](https://github.com/p2p-sys/OpenPRRO) — cash-register (ПРРО) apps.

References
----------

* Certificate format (X.509 v3 profile, Ukrainian): <http://zakon4.rada.gov.ua/laws/show/z1398-12>
* Private key container format (PBES2-like, effective 01.01.2016): <http://zakon3.rada.gov.ua/laws/show/z2227-13>
* Law on Trust Services: <http://zakon.rada.gov.ua/laws/show/2155-19>
* DSTU 7564:2014 (Kupyna hash function) — the Ukrainian national standard.
* Tax report format and implementation details: [dstucrypt/agent](https://github.com/dstucrypt/agent).

License
-------

BSD. Original author: Ilya Petrov.

Bonus
-----

The first known use of the word *Kurwa* was recorded in 1415. Happy 600th
birthday, Kurwa!
