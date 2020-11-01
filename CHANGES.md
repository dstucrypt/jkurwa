API changes

# v1.7.0

- (breaking change) box.unwrap() is now async and returns a promise to accomodate ocsp checks;
- keyPath and certPath in `new Box(opts.keys)` and `box.load()` are deprecated and would be removed soon.
