/*
 * Public entry point for the windowed non-adjacent form (wNAF) scalar
 * multiplication package. Re-exports the wNAF digit encoders (windowNaf,
 * compactNaf, getWindowSize) and the point-multiplication routines
 * (precomp, mulPos) as a single flat namespace consumed by curve.js and
 * point.js.
 */
import * as mul from "./mul.js";
import * as wnaf from "./wnaf.js";

export const precomp = mul.precomp;
export const mulPos = mul.mulPos;
export const getWindowSize = wnaf.getWindowSize;
export const windowNaf = wnaf.windowNaf;
export const compactNaf = wnaf.compactNaf;
