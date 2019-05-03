var asn1 = require('asn1.js'),
    rfc3280 = require('./rfc3280');

var OID = {
    '1 2 804 2 1 1 1 1 3 1 1': "DSTU_4145_LE",
    '1 3 6 1 4 1 19398 1 1 2 3': 'DSTU_4145_KEY_BITS',
    "1 3 6 1 4 1 19398 1 1 2 2": "DSTU_4145_CURVE",
};

var KeyAttrValue = asn1.define('KeyAttrValue', function () {
    this.choice({
        param_d: this.bitstr(),
        dstu4145: this.use(DstuParams),
        unknown: this.any()
    })
});

var KeyAttrValues = asn1.define('KeyAttrValues', function () {
    this.setof(KeyAttrValue);
});

var KeyAttr = asn1.define('Attr', function () {
    this.seq().obj(
        this.key('id').objid(OID),
        this.key('value').use(KeyAttrValues)
    );
});

var Pentanominal = asn1.define('Pentanominal', function () {
    this.seq().obj(
        this.key('k1').int(),
        this.key('k2').int(),
        this.key('k3').int()
    );
});

var Polynomial = asn1.define('Polynomial', function () {
    this.choice({
        trinominal: this.int(),
        pentanominal: this.use(Pentanominal)
    });
});

var CurveParams = asn1.define('CurveParams', function () {
    this.seq().obj(
        this.key('p').seq().obj(
            this.key('param_m').int(),
            this.key('ks').use(Polynomial)
        ),
        this.key('param_a').int(),
        this.key('param_b').octstr(), // inverted
        this.key('order').int(),
        this.key('bp').octstr()
    );
});

var CURVES = {
    '1 2 804 2 1 1 1 1 3 1 1 2 0': 'DSTU_PB_163',
    '1 2 804 2 1 1 1 1 3 1 1 2 1': 'DSTU_PB_167',
    '1 2 804 2 1 1 1 1 3 1 1 2 2': 'DSTU_PB_173',
    '1 2 804 2 1 1 1 1 3 1 1 2 3': 'DSTU_PB_179',
    '1 2 804 2 1 1 1 1 3 1 1 2 4': 'DSTU_PB_191',
    '1 2 804 2 1 1 1 1 3 1 1 2 5': 'DSTU_PB_233',
    '1 2 804 2 1 1 1 1 3 1 1 2 6': 'DSTU_PB_257',
    '1 2 804 2 1 1 1 1 3 1 1 2 7': 'DSTU_PB_307',
    '1 2 804 2 1 1 1 1 3 1 1 2 8': 'DSTU_PB_367',
    '1 2 804 2 1 1 1 1 3 1 1 2 9': 'DSTU_PB_431',
    '1 2 840 10045 3 1 7': 'secp256r1',
};

var Curve = asn1.define('Curve', function () {
    this.choice({
        id: this.objid(CURVES),
        params: this.use(CurveParams),
    });
});

var DstuParams = asn1.define('CurveParams', function () {
    this.seq().obj(
        this.key('curve').use(Curve),
        this.key('dke').optional().octstr(),
        this.key('dke2').optional().octstr()
    );
});
module.exports.DstuParams = DstuParams;
rfc3280.injectPubAlgo('Dstu4145le', DstuParams);
rfc3280.injectPubAlgo('ECDSA', Curve);

var DstuPrivkey = asn1.define('DstuPrivkey', function () {
    this.seq().obj(
        this.key('version').int(),
        this.key('priv0').seq().obj(
            this.key('id').objid(OID),
            this.key('p').seq().obj(
                this.key('p').use(Curve),
                this.key('sbox').optional().octstr()
            )
        ),
        this.key('param_d').octstr(),
        this.key('attr').implicit(0).seqof(KeyAttr)
    );
});

module.exports.DstuPrivkey = DstuPrivkey;


var StoreIIT = asn1.define('StoreIIT', function () {
    this.seq().obj(
        this.key('cryptParam').seq().obj(
            this.key('cryptType').objid({
                "1 3 6 1 4 1 19398 1 1 1 2": "IIT Store",
                '1 2 840 113549 1 5 13': "PBES2",
                "1 2 840 113549 1 5 12": "PBKDF2",
                '1 2 804 2 1 1 1 1 1 2': "GOST_34311_HMAC",
                '1 2 804 2 1 1 1 1 1 1 3': "GOST_28147_CFB",
                '1 2 804 2 1 1 1 1 3 1 1': "DSTU_4145_LE",
            }),
            this.key('cryptParam').seq().obj(
                this.key('mac').octstr(),
                this.key('pad').octstr().optional()
            )
        ),
        this.key('cryptData').octstr()
    );
});

var enc_parse = function (data) {

    var asn1 = StoreIIT.decode(data, 'der'), mac, pad;
    mac = asn1.cryptParam.cryptParam.mac;
    pad = asn1.cryptParam.cryptParam.pad;

    if (mac.length !== 4) {
        throw new Error("Invalid mac len " + mac.length);
    }
    if (pad.length >= 8) {
        throw new Error("Invalid pad len " + pad.length);
    }
    if (asn1.cryptParam.cryptType !== 'IIT Store') {
        throw new Error("Invalid storage type");
    }

    return {
        "format": "IIT",
        "mac": mac,
        "pad": pad,
        "body": asn1.cryptData,
    };
};

module.exports.StoreIIT = StoreIIT;
module.exports.enc_parse = enc_parse;
