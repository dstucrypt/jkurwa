'use strict';
var Buffer = require('buffer').Buffer;
var _pure = require('./gf2m.js');
var impl = _pure;

var Field = function(in_value, fmt, curve) {
    var ob, value, idx, vidx, chr, bpos, code, size;

    if(curve === undefined || curve.mod_words === undefined) {
        throw new Error("pass curve to field constructor");
    }

    if(in_value !== null && in_value._is_field) throw new Error("wtf");

    if(in_value === null) {
        this.bytes = new Uint32Array(curve.mod_words);
        this.length = curve.mod_words;
    } else {
        this.setValue(in_value, fmt, curve.mod_words);
    }

    this._is_field = true;
    this.curve = curve;
    this.mod_bits = curve.mod_bits;
    this.mod_words = curve.mod_words;
}

Field.prototype.toString = function (raw) {
    var txt = '', chr, skip = true,
        _bytes = this.bytes;

    for(var i = _bytes.length-1; i>=0; i--) {
        chr = _bytes[i].toString(16);
        if(skip && _bytes[i] == 0) {
            continue;
        }
        while(chr.length < 8 && skip===false)
            chr = '0' + chr;
        txt += chr;
        skip = false;
    }

    if(raw === true) {
        return txt;
    }

    return '<Field ' + txt + '>';
};

Field.prototype.mod_mul = function (that) {
    var s = this.curve.mod_tmp;
    impl.mul(this.bytes, that.bytes, s);
    s = impl.mod(s, this.mod_bits).subarray(0, this.mod_words);
    return new Field(s, undefined, this.curve);
};

Field.prototype.mod_sqr = function () {
    return this.mod_mul(this);
};

Field.prototype.mod = function () {
    var rbuf = impl.mod(this.bytes, this.mod_bits);
    return new Field(rbuf, undefined, this.curve);
};

Field.prototype.addM = function (that, _from) {
    var that_b = that.bytes,
        that_len = that_b.length,
        this_b = _from || this.bytes,
        to_b = this.bytes,
        iter_len = Math.max((to_b || _from).length, that_len),
        i;

    if (to_b.length < that_len) {
        to_b = new Uint32Array(this.mod_words);
    }

    for(i=0; i < iter_len; i++) {
        to_b[i] = this_b[i] ^ (that_b[i] || 0);
    }

    this.bytes = to_b;
    this.length = to_b.length;
};

Field.prototype.add = function (that) {
    var ret = new Field(null, undefined, this.curve);
    ret.addM(that, this.bytes);
    return ret;
};

Field.prototype.is_zero = function() {
    var blen = this.length, idx;
    for(idx=0; idx<blen; idx++) {
        if(this.bytes[idx] !== 0)
            return false;
    }

    return true;
};

Field.prototype.equals = function(other) {
    var blen = this.length,
        olen = other.length,
        idx,
        bb = this.bytes,
        diff = 0,
        ob = other.bytes;


    while(ob[olen-1] === 0)
        olen--;

    while(bb[blen-1] === 0)
        blen--;

    if (olen != blen) {
        return false;
    }

    for(idx=0; idx<blen; idx++) {
        diff |= this.bytes[idx] ^ ob[idx];
    }

    return diff === 0;
};

Field.prototype.less = function (other) {
    var blen = this.length,
        olen = other.length,
        idx,
        bb = this.bytes,
        diff = 0,
        ob = other.bytes;


    while(ob[olen-1] === 0)
        olen--;

    while(bb[blen-1] === 0)
        blen--;

    if(olen > blen) {
        return true;
    }

    return bb[blen] < ob[olen];
};

Field.prototype.bitLength = function() {
    return _pure.blength(this.bytes);
};

Field.prototype.testBit = function(n) {
    var test_word = Math.floor(n / 32),
        test_bit = n % 32,
        word = this.bytes[test_word],
        mask = 1 << test_bit;

    if(word === undefined)
        return true;

    return (word & mask) !== 0;
};

Field.prototype.clone = function() {
    return new Field(new Uint32Array(this.bytes), undefined, this.curve);
};

Field.prototype.clearBit = function(n) {
    var test_word = Math.floor(n / 32),
        test_bit = n % 32,
        word = this.bytes[test_word],
        mask = 1 << test_bit;

    if(word === undefined)
        return this;

    word ^= word & mask;

    var ret = this.clone()
    ret.bytes[test_word] = word;
    return ret;
};

Field.prototype.setBit = function(n) {
    var test_word = Math.floor(n / 32),
        test_bit = n % 32,
        word = this.bytes[test_word],
        mask = 1 << test_bit;

    if(word === undefined)
        return this;

    var ret = this.clone()
    ret.bytes[test_word] |= mask;
    return ret;
};

Field.prototype.shiftRight = function (bits) {
    if (bits === 0) return this.clone();

    return new Field(_pure.shiftRight(this.bytes, bits, false), undefined, this.curve);
};

Field.prototype.shiftRightM = function (bits) {
    if (bits === 0) return;
    _pure.shiftRight(this.bytes, bits, true);
};

Field.prototype.buf8 = function () {
    var ret = new Uint8Array(this.bytes.length * 4);
    var l = ret.length;
    var idx;

    for (idx = 0; idx < this.bytes.length; idx++) {
        ret[l - idx * 4 - 1] = this.bytes[idx] & 0xFF;
        ret[l - idx * 4 - 2] = this.bytes[idx] >>> 8 & 0xFF;
        ret[l - idx * 4 - 3] = this.bytes[idx] >>> 16 & 0xFF;
        ret[l - idx * 4 - 4] = this.bytes[idx] >>> 24 & 0xFF;
    }

    return ret;
};

Field.prototype.le = function () {
    var bytes = Math.ceil(this.curve.m / 8);
    var data = this.buf8();
    data = Array.prototype.slice.call(data, 0);
    return new Buffer(data.reverse()).slice(0, bytes);
};


Field.prototype.truncate_buf8 = function () {
    var ret = this.buf8(),
        start = ret.length - (
                this.curve.order.bitLength() / 8
        );

    if(start < 0) {
        return ret;
    }

    return ret.subarray(start);
};


Field.prototype.is_negative = function () {
    return false;
};

Field.prototype.trace = function() {
    var bitm_l = this.curve.m;
    var idx;
    var rv = this;

    for (idx = 1; idx <= bitm_l - 1; idx++) {
        rv = rv.mod_mul(rv);
        rv.addM(this);
    }

    return rv.bytes[0] & 1;

};

Field.prototype.setValue = function (in_value, fmt, mod_words) {
    var vidx, bpos, size, value, idx, chr, code;

    if(in_value !== null && in_value._is_field) throw new Error("wtf");

    if((fmt === undefined) || (fmt === 'buf32')) {
        this.bytes = in_value;
        this.length = in_value.length;
        return;
    }

    if(fmt === 'hex') {
        this.bytes = from_hex(in_value, mod_words);
        this.length = this.bytes.length;
        return;
    }

    if (fmt === 'bn') {
        in_value = in_value.toArray();
        fmt = 'buf8';
    }

    if (fmt === 'buf8') {
        this.bytes = from_u8(in_value, mod_words);
        this.length = this.bytes.length;
    }
};

Field.prototype.invert = function(inplace, _reuse_buf) {
    var a = impl.mod(this.bytes, this.mod_bits);
    var p = this.curve.calc_modulus(this.mod_bits);
    impl.inv(a, p, a);

    return new Field(a, undefined, this.curve);
};


var HEX = '0123456789ABCDEF';
var from_hex = function(in_value, max_size) {
    var idx;
    var chr;
    var code;
    var vidx = 0;
    var bpos = 0;
    var size = Math.ceil(in_value.length / 8);
    size = Math.max(size, max_size || size);
    var value = new Uint32Array(size);
    for(idx=in_value.length-1; idx >= 0; idx-- ) {
        chr = in_value.charAt(idx).toUpperCase();
        code = HEX.indexOf(chr);
        bpos = bpos % 8;
        if (code < 0) {
            throw new Error("Wrong input at " + idx);
        }
        value[vidx] |= code << (bpos*4);
        if(bpos == 7) vidx++;
        bpos ++;
    }
    return value;
};

var from_u8 = function(in_value, max_size) {
    var vidx = 0;
    var bpos = 0;
    var size = Math.ceil(in_value.length / 4);
    size = Math.max(size, max_size || size);
    var value = new Uint32Array(size);
    var idx;
    var code;

    if(in_value.toString() === '[object Uint32Array]') {
        throw new Error("fuck off");
    }

    for(idx=in_value.length-1; idx >= 0; idx-- ) {
        code = in_value[idx];
        bpos = bpos % 4;

        if (code < 0) {
            code = 256 + code;
        }
        value[vidx] |= code << (bpos*8);

        if(bpos === 3) vidx++;
        bpos++;
    }

    return value;
};

module.exports = Field;
module.exports.from_hex = from_hex;
module.exports.from_u8 = from_u8;
module.exports.set_impl = function (_impl) {
    impl = _impl;
};
