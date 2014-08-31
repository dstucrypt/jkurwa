var _wnaf = require('./wnaf.js'),
    getWindowSize = _wnaf.getWindowSize,
    windowNaf = _wnaf.windowNaf,
    bitLengths;

bitLengths = new Uint8Array([
    0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8
]);

var precomp = function (point, width) {
    var i, len_off, len, ret, rpos, rneg, twice;

    len_off = width - 2;

    if (len_off < 0 ) {
        len_off = 0;
    }

    len = 1 << len_off;
    rpos = point._precomp.pos;
    rneg = point._precomp.neg;
    i = rpos.length;

    if (!rneg[0]) {
        rneg[0] = point.negate();
    }

    if(len === 1) {
        return {
            pos: rpos,
            neg: rneg,
        };
    }

    twice = point._twice || (point._twice = point.twice());

    for (;i < len; i++) {
        rpos[i] = twice.add(rpos[i-1]);
        rneg[i] = rpos[i].negate();
    }

    return {
        pos: rpos,
        neg: rneg,
    };
};

var mulPos = function (point, big_k) {

    var width = getWindowSize(big_k.bitLength());
    width = Math.max(2, Math.min(16, width));

    var precomps = precomp(point, width);
    var ppos = precomps.pos;
    var pneg = precomps.neg;

    var wnaf = windowNaf(width, big_k);

    var R = point.Inf;

    var i = wnaf.length;

    /*
        * NOTE: We try to optimize the first window using the precomputed points to substitute an
        * addition for 2 or more doublings.
        */
    if (i > 1)
    {
        var wi = wnaf[--i];
        var digit = wi >> 16, zeroes = wi & 0xFFFF;

        var n = Math.abs(digit);
        var table = digit < 0 ? pneg : ppos;

        // Optimization can only be used for values in the lower half of the table
        if ((n << 2) < (1 << width))
        {
            var highest = bitLengths[n];

            // TODO Get addition/doubling cost ratio from curve and compare to 'scale' to see if worth substituting?
            var scale = width - highest;
            var lowBits =  n ^ (1 << (highest - 1));

            var i1 = ((1 << (width - 1)) - 1);
            var i2 = (lowBits << scale) + 1;
            R = table[i1 >>> 1].add(table[i2 >>> 1]);

            zeroes -= scale;

        }
        else
        {
            R = table[n >>> 1];
        }

        R = R.timesPow2(zeroes);
    }

    var wi, digit, n, table, r;
    while (i > 0)
    {
        wi = wnaf[--i];
        digit = wi >> 16, zeroes = wi & 0xFFFF;

        n = Math.abs(digit);
        table = digit < 0 ? pneg : ppos;
        r = table[n >>> 1];

        R = R.twicePlus(r);
        R = R.timesPow2(zeroes);
    }

    return R;
};

module.exports = {
    mulPos: mulPos,
    precomp: precomp,
};
