export default function(fill) {
  return (globalThis.crypto || globalThis.msCrypto).getRandomValues(fill);
}
