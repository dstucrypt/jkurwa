/*
 * Helpers for selecting the right hash function by DSTU algorithm OID name.
 *
 * A hash function may carry an `.algo` tag naming its digest OID:
 *   - GOST 34.311 (legacy, untagged) -> "Gost34311"
 *   - Kupyna / DSTU 7564:2014         -> "Dstu7564-256" | "-384" | "-512"
 *
 * Kupyna (DSTU 7564:2014) is always available: the built-in implementation is
 * seeded into every lookup, so GOST- and Kupyna-signed material is handled with
 * zero configuration. `algo.hash` stays the primary hash (used for signing the
 * legacy profile, key containers, ciphers and the always-GOST subjectKeyId);
 * `algo.hashes` may still supply custom tagged hashes, which take precedence.
 */
import { hash256, hash384, hash512 } from "./kupyna.js";

const KUPYNA_HASHES = [hash256, hash384, hash512];

// digest algorithm name -> DSTU 4145 signature algorithm names that use it
const SIG_FOR_HASH = {
  Gost34311: ["Dstu4145le"],
  "Dstu7564-256": ["Dstu4145le-Dstu7564-256", "Dstu4145le-Dstu7564-256-pb"],
  "Dstu7564-384": ["Dstu4145le-Dstu7564-384", "Dstu4145le-Dstu7564-384-pb"],
  "Dstu7564-512": ["Dstu4145le-Dstu7564-512", "Dstu4145le-Dstu7564-512-pb"]
};

// inverse: DSTU 4145 signature algorithm name -> digest algorithm name
const HASH_FOR_SIG = {};
for (const [digest, sigs] of Object.entries(SIG_FOR_HASH)) {
  for (const sig of sigs) {
    HASH_FOR_SIG[sig] = digest;
  }
}

// Digest OID name implied by a certificate's signatureAlgorithm (defaults to
// GOST 34.311, i.e. legacy DSTU 4145 `Dstu4145le`).
function digestForSig(signatureAlgorithm) {
  return HASH_FOR_SIG[signatureAlgorithm] || "Gost34311";
}

// Friendly aliases for the forced-hash parameter (Box `hashMethod` / sign opts
// `hash`). The two documented values are "gost" and "kupyna"; size-specific and
// OID names are accepted too.
const CHOICE_ALIASES = {
  gost: "Gost34311",
  gost34311: "Gost34311",
  kupyna: "Dstu7564-256",
  kupyna256: "Dstu7564-256",
  "kupyna-256": "Dstu7564-256",
  kupyna384: "Dstu7564-384",
  "kupyna-384": "Dstu7564-384",
  kupyna512: "Dstu7564-512",
  "kupyna-512": "Dstu7564-512"
};

// Resolve a forced-hash choice to a digest OID name, or null for automatic
// (per-certificate) selection. Accepts "gost"/"kupyna"/size aliases, OID names,
// "auto", or a falsy value (= auto).
function digestForChoice(choice) {
  if (!choice || choice === "auto") {
    return null;
  }
  const key = String(choice).toLowerCase();
  return CHOICE_ALIASES[key] || choice;
}

// OID name of the digest algorithm for a given hash function.
function hashAlgo(hash_f) {
  return (hash_f && hash_f.algo) || "Gost34311";
}

function hashList(algo) {
  // Primary hash first (its tag wins for that OID), then any caller-supplied
  // tagged hashes, then the built-in Kupyna implementation as a fallback so
  // Kupyna is always understood without extra setup.
  const list = [];
  if (algo.hash) {
    list.push(algo.hash);
  }
  if (Array.isArray(algo.hashes)) {
    list.push(...algo.hashes);
  }
  list.push(...KUPYNA_HASHES);
  return list.filter((fn, idx, all) => fn && all.indexOf(fn) === idx);
}

// Build lookup maps from an `algo` object:
//   byDigest: digest OID name    -> hash fn  (pick a message's hash by its digestAlgorithm)
//   bySig:    signature OID name  -> hash fn  (Certificate.verifySignature + keyid)
function hashMaps(algo) {
  const byDigest = {};
  const bySig = {};
  for (const fn of hashList(algo)) {
    const name = hashAlgo(fn);
    if (!byDigest[name]) {
      byDigest[name] = fn;
    }
    for (const sig of SIG_FOR_HASH[name] || []) {
      if (!bySig[sig]) {
        bySig[sig] = fn;
      }
    }
  }
  // The subjectKeyIdentifier of DSTU keys is a GOST-34311 digest even on Kupyna
  // certificates; Certificate.verify reads it via hashes.Dstu4145le. Keep that
  // slot pointing at a GOST hash when available, else fall back to the primary.
  if (!bySig.Dstu4145le && algo.hash) {
    bySig.Dstu4145le = byDigest.Gost34311 || algo.hash;
  }
  return { byDigest, bySig };
}

export {
  hashAlgo,
  hashList,
  hashMaps,
  digestForSig,
  digestForChoice,
  SIG_FOR_HASH,
  HASH_FOR_SIG
};
