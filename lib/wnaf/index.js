import * as mul from "./mul.js";
import * as wnaf from "./wnaf.js";

export const precomp = mul.precomp;
export const mulPos = mul.mulPos;
export const getWindowSize = wnaf.getWindowSize;
export const windowNaf = wnaf.windowNaf;
export const compactNaf = wnaf.compactNaf;
