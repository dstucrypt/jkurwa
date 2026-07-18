import fs from "fs";
import assert from "assert";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { expect } from "vitest";
import gost89 from "gost89";
import * as jk from "../lib/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

export function assetPath(filename) {
  return `${__dirname}/data/${filename}`;
}

export function loadAsset(filename) {
  return fs.readFileSync(assetPath(filename));
}

export function loadPriv(filename) {
  return jk.Priv.from_asn1(loadAsset(filename));
}

export function loadPrivPem(filename) {
  return jk.Priv.from_pem(loadAsset(filename));
}

export function loadCert(filename) {
  return jk.Certificate.from_asn1(loadAsset(filename));
}

export function gostBox() {
  const hash = gost89.compat.algos().hash;
  return new jk.Box({
    algo: { hash, hashes: { Gost34311: hash, Dstu4145le: hash } }
  });
}

// Shared verification for the CZO CAdES test examples: load the CA list,
// unwrap the container, and assert the standard "Test\r\n" payload with a
// verified signature and certificate chain.
export async function expectCzoVerified(signatureAsset, caAsset = "CZO-CA-LIST.p7s") {
  const box = gostBox();
  box.loadCAs(loadAsset(caAsset));

  const { content, pipe } = await box.unwrap(loadAsset(signatureAsset));
  expect(content.toString()).toBe("Test\r\n");
  expect(pipe[0].signed).toBe(true);
  expect(pipe[0].cert.verified).toBe(true);
  return { content, pipe };
}

export function assertEqualSaved(buffer, filename) {
  const expected = loadAsset(filename);
  if (!buffer.equals(expected)) {
    throw new assert.AssertionError({
      message: "Buffers are not equal",
      actual: buffer,
      expected: expected,
      operator: "deepEqual"
    });
  }
}
