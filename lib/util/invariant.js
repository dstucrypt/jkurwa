/*
 * Minimal invariant check.
 */
/**
 * Assert a condition: yields an Error when the value is falsy, otherwise true.
 * @param {*} value Condition to check for truthiness.
 * @param {string} text Message used for the returned Error.
 * @returns {Error|boolean} An Error when `value` is falsy; otherwise `true`.
 */
function invariant(value, text) {
  if (!value) {
    return new Error(text);
  }
  return Boolean(invariant);
}

export { invariant };
