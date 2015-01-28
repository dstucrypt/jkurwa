jkurwa
======

GF2m ellipcit curves library in javascript. 

* Supports short Weierstrass curves used in Ukrainian standard DSTU 4145;
* Provides key deriviation for DSTU block ciphers (see https://github.com/muromec/em-gost);
* Encypted containers can be parsed and decrypted if respective cipher implementation is passed. See gost89, node-gost90 and dstucrypt/agent for reference;
* Encrypted and signed messages in wicked PKCS#7 format used by tax office (sta.gov.ua) are supported for both read and write (see jk.Box, jk.util.transport);
* When running on node, "speedup" module node-gf2m can be used for 2x performance boost (see  dstucrypt/agent and node-gf2m packages).

Warning
-------

* Jkurwa does not guarranty constant-time calculcation;
* Jkurwa only verifies signature against public key and does not actually check X.509 certificate validity (use openssl for this).
   
![Yep](https://raw.githubusercontent.com/muromec/ukurwa4145/master/kdpv.jpg)

[![Build Status](https://travis-ci.org/dstucrypt/jkurwa.svg?branch=master)](https://travis-ci.org/dstucrypt/jkurwa)
[![npm module](https://badge.fury.io/js/jkurwa.svg)](https://www.npmjs.org/package/jkurwa)
[![dependencies](https://david-dm.org/dstucrypt/jkurwa.png)](https://david-dm.org/dstucrypt/jkurwa)

Usage
-----

See ./test/ and ./examples/ directories. See dstucrypt/agent repo for example app.

Sister libraries: 

* https://github.com/dstucrypt/ukurwa4145 - DSTU 4145 in Python;
* https://github.com/dstucrypt/gost89 - GOST cipher, hash, mac, key wrapper and container loader in pure js;
* https://github.com/dstucrypt/node-gost89 - same, but with native performance bossters (for node only);
* https://github.com/dstucrypt/em-gost - same as emgost-compiled module (with C source), deprecated;
* https://github.com/dstucrypt/node-gf2m - Native performance booster for jkurwa (gf2m primitives in C);
* https://github.com/dstucrypt/python-gost89 - gost hash for python (2 and 3);
* https://github.com/muromec/zozol - dumb ASN.1 parser and serialisator for python with X509 and wicked CMS schemas;
* https://github.com/dstucrypt/openssl-dstu - patched OpenSSL with DSTU 4145 and GOST family support;
* https://github.com/dstucrypt/dstu-validator - DSTU signature and certificate validator and parser as HTTP API daemon.

Demo site: http://eusign.org/doc

Demo apps: https://github.com/dstucrypt/agent, https://github.com/dstucrypt/dstukeys
Bonus
---

First known use of the word Kurwa was recorded in 1415. Happy 600 birthday Kurwa!
