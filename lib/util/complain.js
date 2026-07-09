/*
 * Deprecation-warning helper. Logs a message together with an `EOLD`
 * ("end of life"/deprecated) error so the call site shows up in the stack
 * trace. Warnings can be muted globally via `EOLD.silent`.
 */
class EOLD extends Error {}

/**
 * Print a deprecation warning to stderr unless `EOLD.silent` is set.
 * @param {string} msg Message describing the deprecated usage.
 * @returns {void}
 */
function complain(msg) {
  if (!EOLD.silent) {
    console.error(msg, new EOLD());
  }
}

export default complain;
export { EOLD };
