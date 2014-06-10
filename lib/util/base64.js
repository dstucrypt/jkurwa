/*jslint plusplus: true, bitwise: true */
'use strict';

var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
    B64_TEST = /[^A-Za-z0-9\+\/\=]/g,
    B64_REPLACE = /[^A-Za-z0-9\+\/\=]/g;

var b64_encode = function (numbrs, line) {
    var ret = [], b1, b2, b3, e1, e2, e3, e4, i = 0;
    while (i < numbrs.length) {

        b1 = numbrs[i++];
        b2 = numbrs[i++];
        b3 = numbrs[i++];

        e1 = b1 >> 2;
        e2 = ((b1 & 3) << 4) | (b2 >> 4);
        e3 = ((b2 & 15) << 2) | (b3 >> 6);
        e4 = b3 & 63;

        ret.push(B64.charAt(e1));
        ret.push(B64.charAt(e2));
        ret.push(B64.charAt(e3));
        ret.push(B64.charAt(e4));

        if ((i > 0) && (line !== undefined) && ((i % line) === 0)) {
            ret.push('\n');
        }
    }
    return ret.join("");
};

var b64_decode = function (input) {
    var output, output_len,
        chr1, chr2, chr3,
        enc1, enc2, enc3, enc4,
        i = 0,
        o = 0;

    // remove all characters that are not A-Z, a-z, 0-9, +, /, or =
    if (B64_TEST.exec(input)) {
        throw new Error("invalid b64 input");
    }

    input = input.replace(B64_REPLACE, "");
    output_len = Math.floor((input.length + 2) * 3 / 4);
    output = new Buffer(output_len);

    do {
        enc1 = B64.indexOf(input.charAt(i++));
        enc2 = B64.indexOf(input.charAt(i++));
        enc3 = B64.indexOf(input.charAt(i++));
        enc4 = B64.indexOf(input.charAt(i++));

        chr1 = (enc1 << 2) | (enc2 >> 4);
        chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
        chr3 = ((enc3 & 3) << 6) | enc4;

        output[o++] = chr1;
        output[o++] = chr2;
        output[o++] = chr3;

    } while (i < input.length);

    return output;
};


module.exports.b64_encode = b64_encode;
module.exports.b64_decode = b64_decode;
