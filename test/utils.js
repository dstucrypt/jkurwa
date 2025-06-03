import fs from "fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
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
