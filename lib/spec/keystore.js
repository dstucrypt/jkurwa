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

var DstuParams = asn1.define('CurveParams', function () {
    this.seq().obj(
        this.key('curve').use(CurveParams),
        this.key('dke').optional().octstr(),
        this.key('dke2').optional().octstr()
    );
});
module.exports.DstuParams = DstuParams;

var DstuPrivkey = asn1.define('DstuPrivkey', function () {
    this.seq().obj(
        this.key('version').int(),
        this.key('priv0').seq().obj(
            this.key('id').objid(OID),
            this.key('p').seq().obj(
                this.key('p').use(CurveParams),
                this.key('sbox').octstr()
            )
        ),
        this.key('param_d').octstr(),
        this.key('attr').implicit(0).seqof(KeyAttr)
    );
});

module.exports.DstuPrivkey = DstuPrivkey;

// Dirty OOP crap from frozen moscovites hell.
var PubkeyAlgorithmIdentifier = asn1.define('KeyEncryptionAlgorithmIdentifier', function() {
    this.seq().obj(
        this.key('algorithm').objid(rfc3280.ALGORITHMS_IDS),
        this.key('parameters').use(DstuParams)
  );
});
rfc3280.injectPubAlgo(PubkeyAlgorithmIdentifier);
