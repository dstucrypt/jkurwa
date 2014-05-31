all: build

build: jsbn.packed.js

jsbn.packed.js: jsbn.js jsbn2.js export.js fake_navi.js
	cat fake_navi.js jsbn.js jsbn2.js export.js > $@

