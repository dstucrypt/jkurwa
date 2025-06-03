export default function(fill) {
  return (global.crypto || global.msCrypto).getRandomValues(fill);
}
