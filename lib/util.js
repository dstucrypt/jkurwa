/*jslint plusplus: true */
'use strict';

var add_zero = function (u8, reorder) {
    var ret = [], i;
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
};
