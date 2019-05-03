var shiftRight = require('../gf2m.js').shiftRight;

var DEFAULT_CUTOFFS = [
    13, 41, 121, 337, 897, 2305
];



var windowNaf = function (width, bigint) {
    var wnaf, ret_len;
    bigint = bigint.clone();

    if(width === 2) {
        return compactNaf(bigint);
    }

    ret_len = Math.floor(bigint.bitLength() / width + 1)
    wnaf = new Int32Array(ret_len);

    // 2^width and a masbigint and sign bit set accordingly
    var pow2 = 1 << width;
    var masbigint = pow2 - 1;
    var sign = pow2 >>> 1;

    var carry = false;
    var length = 0, pos = 0;
    var digit, zeroes;

    while (pos <= bigint.bitLength())
    {
        if (bigint.testBit(pos) === carry)
        {
            ++pos;
            continue;
        }

        bigint.shiftRightM(pos);

        digit = bigint.bytes[0] & masbigint;

        if (carry)
        {
            ++digit;
        }

        carry = (digit & sign) !== 0;
        if (carry)
        {
            digit -= pow2;
        }

        zeroes = length > 0 ? pos - 1 : pos;
        wnaf[length++] = (digit << 16) | zeroes;
        pos = width;
    }

    // Reduce the WNAF array to its actual length
    if (wnaf.length > length)
    {
        wnaf = wnaf.subarray(0, length);
    }

    return wnaf;
};

var compactNaf = function (k)
{
    if ((k.bitLength() >>> 16) != 0)
    {
        throw new Error("'k' must have bitlength < 2^16");
    }
    if (k.signum() == 0)
    {
        return new Int32Array(0);
    }

    var _3k = k.shiftLeft(1).add(k);
    var bits = _3k.bitLength();
    var naf = new Int32Array(bits >> 1);

    var diff = _3k.xor(k);

    var highBit = bits - 1, length = 0, zeroes = 0;
    var i, digit;
    for (i = 1; i < highBit; ++i)
    {
        if (!diff.testBit(i))
        {
            ++zeroes;
            continue;
        }

        digit  = k.testBit(i) ? -1 : 1;
        naf[length++] = (digit << 16) | zeroes;
        zeroes = 1;
        ++i;
    }

    naf[length++] = (1 << 16) | zeroes;

    if (naf.length > length)
    {
        naf = naf.subarray(0, length);
    }

    return naf;
};

var _getWindowSize = function (bits, cutoffs) {
    var i, cuts = cutoffs.length;

    for (i=0; i < cuts; ++i) {
        if (bits < cutoffs[i]) {
            break;
        }
    }

    return i + 2;
};

var getWindowSize = function(bits) {
    return _getWindowSize(bits, DEFAULT_CUTOFFS);
};

module.exports = {
    getWindowSize: getWindowSize,
    windowNaf: windowNaf,
    compactNaf: compactNaf
};
