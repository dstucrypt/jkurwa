/*jslint plusplus: true, bitwise: true */
'use strict';

var add_zero = function (u8, reorder) {
    var ret = [], i;

    if (u8.toBuffer !== undefined) {
        u8 = u8.toBuffer();
    }

    if (reorder !== true) {
        ret.push(0);
    }
    for (i = 0; i < u8.length; i++) {
        ret.push(u8[i]);
    }

    if (reorder === true) {
        ret.push(0);
        ret = ret.reverse();
    }
    return ret;
};


var invert = function (u8) {
    /*
     * Invert should mask number of "unsed" bits from input.
     * Hoever this bits shold be zeroes and it's safe to
     * ignore them.
     *  mask = 0xFF >>> unused;
     *  */
    var i, cr, ret = [];
    for (i = u8.length - 1; i >= 0; i--) {
        cr = u8[i];
        cr = (
            cr >> 7          | (cr >> 5) &  2 | (cr >> 3) &  4 | (cr >> 1) & 8
            | (cr << 1) & 16 | (cr << 3) & 32 | (cr << 5) & 64 | (cr << 7) & 128
        );
        ret.push(cr);
    }

    return ret;
};

var HEX_REGEXP = /^[A-Fa-f0-9]+$/;

var is_hex = function (inp) {
    var res;

    if ((typeof inp) !== 'string') {
        return false;
    }

    res = inp.match(HEX_REGEXP);
    if (res === null) {
        return false;
    }

    return res.length > 0;
};

module.exports = {
    add_zero: add_zero,
    is_hex: is_hex,
    invert: invert,
};
