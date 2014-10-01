'use strict';

var bstring = function (_bytes) {
    var txt = '', chr, skip = true;
    var i;

    for(i = _bytes.length-1; i>=0; i--) {
        chr = _bytes[i].toString(16);
        while(chr.length < 8 && skip===false) {
            chr = '0' + chr;
        }
        txt += chr + " ";
        skip = false;
    }

    return '<b ' + txt + '>';
};

var blength = function(_bytes) {
    var r = 1, t, x, nz;
    nz = _bytes.length - 1;
    while(_bytes[nz] === 0) {
        nz--;
    }

    x = _bytes[nz];
    if((t=x>>>16) != 0) { x = t; r += 16; }
    if((t=x>>8) != 0) { x = t; r += 8; }
    if((t=x>>4) != 0) { x = t; r += 4; }
    if((t=x>>2) != 0) { x = t; r += 2; }
    if((t=x>>1) != 0) { x = t; r += 1; }
    return r + nz * 32;
};


/* _bytes should be Uint32Array */
var _shiftRight = function(_bytes, right, inplace) {
    var wright = Math.floor(right / 32),
        right = right % 32,
        idx, blen = _bytes.length,
        left = 32 - right,
        mask_f = (1 << (1+right)) -1,
        _rbytes,
        tmp;

    if(right == 31) mask_f = 0xffffffff;

    if(inplace === true) {
        _rbytes = _bytes;
    } else {
        _rbytes = new Uint32Array(blen);
    }

    _rbytes[0] = _bytes[0] >>> right;
    for(idx = 1; idx < blen; idx++) {
        tmp = _bytes[idx] & mask_f;

        _rbytes[idx] = _bytes[idx] >>> right;
        _rbytes[idx-1] |= tmp << left;
    }

    if(wright == 0)
        return _rbytes;

    for(idx = 0; idx < blen; idx++) {
        _rbytes[idx] = _rbytes[idx + wright] || 0;
    }

    return _rbytes;
};

var l1ShiftXor = function(b, r) {
    var t, i, c;
    for(i=b.length-1; i>= 0; --i) {
        t = b[i]==(b[i] & 0x7fffffff) ? 0 : 1;
        r[i+1] ^= t|c;
        c = (b[i]&0x7fffffff)<<1;
    }
    r[0] ^= c;
    return r;
}

var lShiftXor = function(b, ls, r) {
    var wls = ls >> 5,
        ls = ls % 32,
        i, l = b.length + wls + 1,
        rs = 32 - ls,
        lm = (1 << rs) -1;

    var c = 0;
    for(i = l-1; i>=0; i--) {
        r[i+1+wls] ^= c|(b[i]>>>rs);
        c = (b[i]&lm)<<ls;
    }
    r[wls] ^= c;
}

var mul_1x1 = function (ret, offset, a, b) {
    var tab, top2b = a >>> 30;
    var a1, a2, a4;
    var ol = offset, oh = offset + 1;
    var s, l, h;

    a1 = a & (0x3FFFFFFF); a2 = a1 << 1; a4 = a2 << 1;

    tab  =  [
        0, a1, a2, a1^a2,
        a4, a1^a4, a2^a4, a1^a2^a4
    ];

    s = tab[b       & 0x7]; l  = s;
    s = tab[b >>>  3 & 0x7]; l ^= s <<  3; h  = s >>> 29;
    s = tab[b >>>  6 & 0x7]; l ^= s <<  6; h ^= s >>> 26;
    s = tab[b >>>  9 & 0x7]; l ^= s <<  9; h ^= s >>> 23;
    s = tab[b >>> 12 & 0x7]; l ^= s << 12; h ^= s >>> 20;
    s = tab[b >>> 15 & 0x7]; l ^= s << 15; h ^= s >>> 17;
    s = tab[b >>> 18 & 0x7]; l ^= s << 18; h ^= s >>> 14;
    s = tab[b >>> 21 & 0x7]; l ^= s << 21; h ^= s >>> 11;
    s = tab[b >>> 24 & 0x7]; l ^= s << 24; h ^= s >>>  8;
    s = tab[b >>> 27 & 0x7]; l ^= s << 27; h ^= s >>>  5;
    s = tab[b >>> 30      ]; l ^= s << 30; h ^= s >>>  2;


    if (top2b & 1) { l ^= b << 30; h ^= b >>> 2; }
    if (top2b & 2) { l ^= b << 31; h ^= b >>> 1; }

    ret[offset + 1] = h;
    ret[offset] = l;
};

var mul_2x2 = function (a1, a0, b1, b0, ret) {
    mul_1x1(ret, 2, a1, b1);
    mul_1x1(ret, 0, a0, b0);
    mul_1x1(ret, 4, a0 ^ a1, b0 ^ b1);

    ret[2] ^= ret[5] ^ ret[1] ^ ret[3];
    ret[1] = ret[3] ^ ret[2] ^ ret[0] ^ ret[4] ^ ret[5];
    ret[4] = 0; ret[5] = 0;

    return ret;
}

var fmod_mul = function(a, b, modulus) {
    var s, y1, y0, x1, x0, x22, i, j, a_len, b_len;

    a_len = a.length;
    b_len = b.length;

    s = new Uint32Array(a.length + b.length + 4);
    x22 = new Uint32Array(6);

    for(j = 0; j < b_len; j+= 2) {
        y0 = b[j];
        y1 = ((j+1) == b_len) ? 0 : b[j+1];

        for(i = 0; i < a_len; i+= 2) {
            x0 = a[i];
            x1 = ((i+1) == a_len) ? 0 : a[i+1];

            mul_2x2(x1, x0, y1, y0, x22);
            s[j+i+0] ^= x22[0];
            s[j+i+1] ^= x22[1];
            s[j+i+2] ^= x22[2];
            s[j+i+3] ^= x22[3];
        }

    }

    return fmod(s, modulus);
}

var BITS = 32;

var fmod = function (a, p, inplace) {
    var ret;
    var ret_len;
    var zz, k, n, d0, d1;
    var tmp_ulong;

    if(inplace) {
        ret_len = a.length;
        ret = a.subarray(0, ret_len);
    } else {
        ret_len = a.length;
        ret = new Uint32Array(ret_len);
        for(k=0; k < ret_len; k++)
            ret[k] = a[k];
    }

    /* start reduction */
    var dN = Math.floor(p[0] / BITS);
    for (var j = ret_len - 1; j > dN;)
    {
        zz = ret[j];
        if (ret[j] == 0) { j--; continue; }
        ret[j] = 0;

        for (k = 1; p[k]; k++)
        {
            /* reducing component t^p[k] */
            n = p[0] - p[k];
            d0 = n % BITS;
            d1 = BITS - d0;
            n = Math.floor(n / BITS);
            ret[j-n] ^= (zz>>>d0);
            if (d0) ret[j-n-1] ^= (zz<<d1);
        }

        /* reducing component t^0 */
        n = dN;
        d0 = p[0] % BITS;
        d1 = BITS - d0;
        ret[j-n] ^= (zz >>> d0);
        if (d0) ret[j-n-1] ^= (zz << d1);

    }

    /* final round of reduction */
    while (j === dN)
    {
        d0 = p[0] % BITS;
        zz = ret[dN] >>> d0;
        if (zz == 0) break;
        d1 = BITS - d0;

        /* clear up the top d1 bits */
        if (d0)
            ret[dN] = (ret[dN] << d1) >>> d1;
        else
            ret[dN] = 0;
        ret[0] ^= zz; /* reduction t^0 component */

        for (k = 1; p[k]; k++)
        {
            /* reducing component t^p[k]*/
            n = Math.floor(p[k] / BITS);
            d0 = p[k] % BITS;
            d1 = BITS - d0;
            ret[n] ^= (zz << d0);
            tmp_ulong = zz >>> d1;
            if (d0 && tmp_ulong)
                    ret[n+1] ^= tmp_ulong;
         }
    }

    var strip = ret.length-1;
    while(ret[strip] === 0)
        strip--;

    ret = ret.subarray(0, strip+1);
    return ret;
};

var finv = function(ob, inplace, _reuse_buf) {
    var b = new Uint32Array(ob.mod_words),
        c = new Uint32Array(ob.mod_words),
        p, u, v, j, tmp, tmp_c, tmp_v, idx,
        ubits, vbits;

    b[0] = 1;
    u = fmod(ob.bytes, ob.mod_bits, inplace);
    v = ob.curve.calc_modulus(ob.mod_bits);
    p = ob.curve.calc_modulus(ob.mod_bits);

    ubits = blength(u);
    vbits = blength(v);

    var u0, u1, b0, b1, mask;

    while (1) {
        if (ubits < 0) throw new Error("Internal error");
        while(ubits && !(u[0] & 1)) {
            u0 = u[0];
            b0 = b[0];

            mask = b0 & 1 ? 0xffffffff : 0;
            b0 ^= p[0] & mask;

            for(idx=0; idx<p.length-1; idx++) {
                u1 = u[idx+1];
                u[idx] = ((u0>>>1)|(u1<<31));
                u0 = u1;
                b1 = b[idx+1] ^ (p[idx+1] & mask);
                b[idx] = ((b0>>>1)|(b1<<31));
                b0 = b1;
            }

            u[idx] = u0>>1;
            b[idx] = b0>>1;
            ubits --;
        }

        if(ubits<=32 && u[0]==1) break;

        if(ubits < vbits) {
            tmp = ubits; ubits = vbits; vbits = tmp;
            tmp = u; u = v; v = tmp;
            tmp = b; b = c; c = tmp;
        }

        for(idx=0; idx<p.length; idx++) {
            u[idx] ^= v[idx];
            b[idx] ^= c[idx];
        }

        if(ubits === vbits) {
            ubits = blength(u);
        }

    }
       
    return new Field(b, undefined, ob.curve);
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
    var rbuf = fmod_mul(this.bytes, that.bytes, this.mod_bits);
    return new Field(rbuf, undefined, this.curve);
};

Field.prototype.mod_sqr = function () {
    var rbuf = fmod_mul(this.bytes, this.bytes, this.mod_bits);
    return new Field(rbuf, undefined, this.curve);
};

Field.prototype.mod = function () {
    var rbuf = fmod(this.bytes, this.mod_bits);
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
    return blength(this.bytes);
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

    return new Field(_shiftRight(this.bytes, bits, false), undefined, this.curve);
};

Field.prototype.shiftRightM = function (bits) {
    if (bits === 0) return;
    _shiftRight(this.bytes, bits, true);
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


Field.prototype.truncate_buf8 = function () {
    var ret = this.buf8(),
        start = ret.length - (
                this.curve.order.bitLength() / 8
        );

    if(start < 0) {
        return ret;
    }

    if(ret.slice) {
        return ret.slice(start);
    } else {
        return ret.subarray(start);
    }
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
    return finv(this, inplace, _reuse_buf);
};

module.exports = {
    mul_2x2: mul_2x2,
    mod_mul: fmod_mul,
    Field: Field,
    shiftRight: _shiftRight,
    lShiftXor: lShiftXor,
    l1ShiftXor: l1ShiftXor,
    bstring: bstring,
    from_hex: from_hex,
    from_u8: from_u8,
}
