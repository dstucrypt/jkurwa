jkurwa
======

GF2m ellipcit curves library in javascript. 

* Supports short Weierstrass curves used in Ukrainian standard DSTU 4145;
* Provides key deriviation for DSTU block ciphers (see https://github.com/muromec/em-gost);
* Encypted containers can be parsed and decrypted if respective cipher implementation is passed. See gost89 and dstucrypt/agent for reference;
* Encrypted and signed messages in wicked PKCS#7 format used by tax office (sta.gov.ua) are supported for both read and write (see jk.Box, jk.util.transport);
* Includes parsers for signed and encrypted messages, X509.v3 certificates, JKS and Key-6.dat key containers, TSP, CMP, OCSP requests and responses.

Warning
-------

* Jkurwa does not guarranty constant-time calculcation;
* Jkurwa only verifies signature against public key and does not actually check X.509 certificate validity (use openssl for this).
   
![Yep](https://raw.githubusercontent.com/muromec/ukurwa4145/master/kdpv.jpg)

[![Build Status](https://travis-ci.org/dstucrypt/jkurwa.svg?branch=master)](https://travis-ci.org/dstucrypt/jkurwa)
[![codecov](https://codecov.io/gh/dstucrypt/jkurwa/branch/master/graph/badge.svg)](https://codecov.io/gh/dstucrypt/jkurwa)
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

Demo site: https://dstucrypt.github.io/signerbox2/

Demo apps:

* https://github.com/dstucrypt/agent -- command line utility to sign, encrypt and decrypt tax reports
* https://github.com/dstucrypt/dstukeys -- web interface with examples of authentication
* https://github.com/dstucrypt/signerbox2/ -- another web app

To cross-verifiy signatures use https://czo.gov.ua/verify

References
----------

* Certificate format (in Ukrainian), basically kind of X.509v3: http://zakon4.rada.gov.ua/laws/show/z1398-12
* Private key container format, PBES2-like (effective from 01.01.2016): http://zakon3.rada.gov.ua/laws/show/z2227-13
* See https://github.com/dstucrypt/agent repo for tax report format and implementation details
* Law on Trust Services - http://zakon.rada.gov.ua/laws/show/2155-19

Bonus
---

First known use of the word Kurwa was recorded in 1415. Happy 600 birthday Kurwa!
