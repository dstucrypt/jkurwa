/*jslint plusplus: true, bitwise: true */
'use strict';

var asn1 = require('asn1.js'),
    Buffer = require('buffer').Buffer,
    pbes2 = require('../spec/pbes.js'),
    keystore = require('../spec/keystore.js'),
    models = require('../models/index.js'),
    pem = require('../util/pem.js'),
    util = require('../util.js');


var Keycoder = function () {
    console.warn("Keycoder instances are deprecated. Use jk.guess_parse() to parse keys");
};


var is_valid = function (indata) {
    return (indata[0] === 0x30) && ((indata[1] & 0x80) === 0x80);
};


var privkey_parse = function (data) {
    return models.Priv.from_asn1(data, true);
};

var cert_parse = function (data) {
    return models.Certificate.from_asn1(data);
};

var parsers = [
    keystore.enc_parse,
    pbes2.enc_parse,
    pbes2.enc_parse2,
    privkey_parse,
    cert_parse,
];

var guess_parse = function (indata) {
    var i;

    if (!Buffer.isBuffer(indata)) {
        indata = new Buffer(indata, 'binary');
    }

    indata = pem.maybe_pem(indata);

    for (i = 0; i < parsers.length; i++) {
        try {
            return parsers[i](indata);
        } catch (ignore) {}
    }

    throw new Error("Unknown format");
};

Keycoder.prototype.is_valid = is_valid;
Keycoder.prototype.is_pem = pem.is_pem;
Keycoder.prototype.maybe_pem = pem.maybe_pem;
Keycoder.prototype.parse = guess_parse;

module.exports = Keycoder;
module.exports.guess_parse = guess_parse;
