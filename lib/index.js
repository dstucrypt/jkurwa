/*
 * Public entry point of the jkurwa library.
 *
 * Aggregates the modules that make up the package's public API and re-exports
 * them from a single place. The default export is the `Box` context (from
 * app/ctx.js); the named exports expose the DSTU 4145 EC primitives and the
 * higher-level helpers:
 *   - b64_decode / b64_encode: base64 helpers
 *   - Curve, Field, pkey, pubkey, std_curve: elliptic-curve math and key factories
 *   - transport: transport-container (encrypted message) helpers
 *   - Priv, Pub, Certificate: key/certificate models
 *   - standard: named standard curve definitions
 *   - dstszi2010, rfc3280, rfc3161: ASN.1 spec submodules
 *   - Keycoder, guess_parse: key/container parsing
 *   - Box: crypto context / facade
 *   - models: full model namespace
 */
import { Priv, Pub, Certificate } from "./models/index.js";
import * as models from "./models/index.js";
import * as dstszi2010 from "./spec/dstszi2010.js";
import * as rfc3280 from "./spec/rfc3280.js";
import rfc3161 from "./spec/rfc3161-tsp.js";
import Keycoder, { guess_parse } from "./app/keycoder.js";
import Box from "./app/ctx.js";
import { b64_encode, b64_decode } from "./util/base64.js"; // consider changing this one to standart
import transport from "./util/transport.js";
import * as standard from "./standard.js";
import { Curve, Field, pkey, pubkey, std_curve } from "./curve.js";

export default Box;

export {
  b64_decode,
  b64_encode,
  Curve,
  Field,
  pkey,
  pubkey,
  std_curve,
  transport,
  Priv,
  Pub,
  Certificate,
  // curve definitions
  standard,
  // submodules
  dstszi2010,
  rfc3280,
  rfc3161,
  Keycoder,
  guess_parse,
  Box,
  models
};
