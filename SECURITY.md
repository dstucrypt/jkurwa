# Security Policy

jkurwa implements Ukrainian national cryptography (DSTU 4145 signatures,
GOST 34.311 / DSTU 7564 "Kupyna" hashes) and the PKI formats built on top of
them. Security reports are very welcome.

## Supported versions

Only the latest release published on npm receives security fixes. There are
no maintenance branches for older versions.

## Reporting a vulnerability

Please use **GitHub private vulnerability reporting**: open the repository's
**Security** tab and click **"Report a vulnerability"**. This creates a
private advisory visible only to the maintainers.

Please do **not** report security issues through public GitHub issues,
discussions or pull requests.

A useful report includes: the affected API (e.g. `Box.unwrap`, key container
parsing), a minimal reproduction (input bytes or a script), and the impact
you believe it has (signature forgery, key extraction, denial of service...).

You should get an initial response within two weeks. Coordinated disclosure
is appreciated — give the maintainers a reasonable window to ship a fix
before publishing details.

## Scope — what is *not* a vulnerability here

The following are documented, deliberate limitations (see the
[README](./README.md#security-notes--known-limitations)), not reportable
vulnerabilities on their own:

- **Timing side channels.** jkurwa does not guarantee constant-time
  computation. Do not use it where a local attacker can measure timing.
- **No chain validation without a CA store.** Signature verification alone
  does not validate the X.509 certificate chain; load a CA list with
  `box.loadCAs(...)` to get chain checks.
- **Lenient X.509 parsing.** Version/field consistency (e.g. extensions on a
  v1 certificate) is not enforced, to stay compatible with real-world CA
  output.
- **Partial CMP support** — only certificate fetching is modelled.

A report that *escalates* one of these into something concrete (e.g. a
practical key-recovery attack via timing, or a chain-validation bypass with
a CA store loaded) is absolutely in scope.
