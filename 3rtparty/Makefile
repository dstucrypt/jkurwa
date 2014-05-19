all: build

build: jsbn.packed.js

jsbn.packed.js: jsbn.js jsbn2.js export.js
	cat jsbn.js jsbn2.js export.js > $@

