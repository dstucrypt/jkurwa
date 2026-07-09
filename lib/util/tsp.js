/*
 * Predicates for interpreting the timestamp (TSP) mode selector, whose value is
 * one of "all", "content", "signature" (or absent). "all" enables both the
 * content and signature timestamps.
 */
/**
 * Whether a content timestamp is requested for the given mode.
 * @param {string} value TSP mode ("all" | "content" | "signature" | ...).
 * @returns {boolean} True for "all" or "content".
 */
const useContentTsp = value => ["all", "content"].includes(value);
/**
 * Whether a signature timestamp is requested for the given mode.
 * @param {string} value TSP mode ("all" | "content" | "signature" | ...).
 * @returns {boolean} True for "all" or "signature".
 */
const useSignatureTsp = value => ["all", "signature"].includes(value);

export { useContentTsp, useSignatureTsp };
