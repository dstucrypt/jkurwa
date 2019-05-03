'use strict';

var util = require('../util.js'),
    Field = require('../field.js'),
    Buffer = require('buffer').Buffer;

var detect_format = function (inp) {
    if (util.is_hex(inp) === true) {
        return 'hex';
    }
    if(inp.buffer !== undefined) {
        return 'raw';
    }

    throw new Error("Unknown pubkey format");
};


var detect_sign_format = function(sign) {
    if (sign.hasOwnProperty && sign.hasOwnProperty('s') && sign.hasOwnProperty('r')) {
        return 'split';
    }
    if ((typeof sign) === 'string' || Buffer.isBuffer(sign)) {
        return 'short';
    }

};


var parse_sign = function(sign, fmt, curve) {
    if (fmt === 'short') {
        if(!Buffer.isBuffer(sign)) {
            sign = Buffer(sign);
        }

        if(sign[0] !== 4 || sign[1] !== (sign.length - 2)) {
            throw Error("Broken short sign");
        }
        sign = sign.slice(2);
        fmt = 'le';
    }

    if (fmt === 'le') {
        var len = sign.length;
        var r = sign.slice(0, Math.ceil(len / 2)),
            s = sign.slice(r.length);

        sign = {
            s: util.add_zero(s, true),
            r: util.add_zero(r, true),
        };
        fmt = 'split';
    }

    if (fmt === 'split') {
        if((typeof sign.s) === 'string') {
            sign.s = Buffer(sign.s);
        }
        if((typeof sign.r) === 'string') {
            sign.r = Buffer(sign.r);
        }

        return {
            s: new Field(sign.s, 'buf8', curve),
            r: new Field(sign.r, 'buf8', curve),
        };
    }

};

var Pub = function (p_curve, point_q, compressed) {
    this.x = point_q.x;
    this.y = point_q.y;
    this.point = point_q;
    this.curve = p_curve;
    this._cmp = compressed;
    this.type = 'Pub';
};

Pub.prototype.compress = function() {
    if(!this._cmp) {
        this._cmp = this.point.compress();
    }
    return this._cmp;
};

Pub.prototype.verify = function (hash_val, sign, fmt) {
    if(fmt === undefined) {
        fmt = detect_sign_format(sign);
    }
    if(Buffer.isBuffer(hash_val)) {
        hash_val = new Field(util.add_zero(hash_val, true), 'buf8', this.curve);
    }

    sign = parse_sign(sign, fmt, this.curve);
    return this.help_verify(hash_val, sign.s, sign.r);
};

Pub.prototype.help_verify = function (hash_val, s, r) {
    if (s.is_zero()) {
        throw new Error("Invalid sig component S");
    }
    if (r.is_zero()) {
        throw new Error("Invalid sig component R");
    }

    if (this.curve.order.less(s)) {
        throw new Error("Invalid sig component S");
    }
    if (this.curve.order.less(r) < 0) {
        throw new Error("Invalid sig component R");
    }

    var mulQ, mulS, pointR, r1;
    hash_val = hash_val._is_field ? hash_val : new Field(hash_val, 'bn', this.curve);

    mulQ = this.point.mul(r);
    mulS = this.curve.base.mul(s);

    pointR = mulS.add(mulQ);
    if (pointR.is_zero()) {
        throw new Error("Invalid sig R point at infinity");
    }

    r1 = pointR.x.mod_mul(hash_val);
    r1 = this.curve.truncate(r1);

    return r.equals(r1);
};

Pub.prototype.validate = function () {
    var pub_q = this.point, pt;

    if (pub_q.is_zero()) {
        return false;
    }

    if (this.curve.contains(pub_q) === false) {
        return false;
    }

    pt = pub_q.mul(this.curve.order);
    if (!pt.is_zero()) {
        return false;
    }

    return true;
};

Pub.prototype.serialize = function () {
    var buf = new Buffer(this.compress().buf8(), 'binary');
    var cut = buf.length - Math.ceil(this.curve.m/8);

    var inverse = new Buffer(buf.length + 2 - cut);
    var i;
    for (i=2; i<inverse.length; i++) {
        inverse[i] = buf[buf.length + 1 - i];
    }
    inverse[0] = 0x04;
    inverse[1] = buf.length - cut;
    return inverse;
};

Pub.prototype.keyid = function (algos) {
    return algos.hash(this.serialize());
};


module.exports = Pub;
module.exports.detect_format = detect_format;
module.exports.parse_sign = parse_sign;
