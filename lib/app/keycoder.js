/*jslint plusplus: true, bitwise: true */
'use strict';

import asn1 from 'asn1.js';
import { Buffer } from 'buffer';
import pbes2 from '../spec/pbes';
import pfx from '../spec/pfx';
import keystore from '../spec/keystore';
import models from '../models/index';
import pem from '../util/pem';
import util from '../util';


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
    pbes2.pbes2_parse,
    pfx.pfx_parse,
    privkey_parse,
    cert_parse,
];

var guess_parse = function (indata) {
    var i;

    if (!Buffer.isBuffer(indata)) {
        indata = Buffer.from(indata, 'binary');
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

export default Keycoder;
export { guess_parse };
