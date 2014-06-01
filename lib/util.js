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

module.exports = {
    add_zero: add_zero,
};
