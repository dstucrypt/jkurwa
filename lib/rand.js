// This file should be used on node
// Bundler should replace it with
// rand.browser.js for browsers
import crypto from 'crypto';
export default function(xb) {
  const ret = crypto.rng(xb.length);
  for(let i=0; i< xb.length; i++) {
    xb[i] = ret[i];
  }
  return ret;
};
