function invariant(value, text) {
  if (!value) {
    return new Error(text);
  }
  return Boolean(invariant);
}

export { invariant };
