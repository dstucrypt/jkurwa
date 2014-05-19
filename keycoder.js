var asn1 = require('asn1.js'),
    Buffer = require('buffer').Buffer;

var Keycoder = function() {

    var OID = {
        "1 3 6 1 4 1 19398 1 1 1 2": "IIT Store",
        '1 2 840 113549 1 5 13': "PBES2",
        "1 2 840 113549 1 5 12": "PBKDF2",
        '1 2 804 2 1 1 1 1 1 2': "GOST_34311_HMAC",
        '1 2 804 2 1 1 1 1 1 1 3': "GOST_28147_CFB",
        '1 2 804 2 1 1 1 1 3 1 1': "DSTU_4145_LE",
    },
    PEM_KEY_B = '-----BEGIN PRIVATE KEY-----',
    PEM_KEY_E = '-----END PRIVATE KEY-----';

    var ob = {
        StoreIIT: asn1.define('StoreIIT', function() {
            this.seq().obj(
                this.key('cryptParam').seq().obj(
                    this.key('cryptType').objid(OID),
                    this.key('cryptParam').seq().obj(
                        this.key('mac').octstr(),
                        this.key('pad').octstr()
                    )
                    ),
                this.key('cryptData').octstr()
            );
        }),
        StorePBES2: asn1.define("StorePBES2", function() {
            this.seq().obj(
                this.key("head").seq().obj(
                    this.key("id").objid(OID),
                    this.key("p").seq().obj(
                        this.key("key").seq().obj(
                            this.key("id").objid(OID),
                            this.key("p").seq().obj(
                                this.key("salt").octstr(),
                                this.key("cycles").int(),
                                this.key("cipher").seq().obj(
                                    this.key("id").objid(OID),
                                    this.key("null").null_()
                                )
                            )
                        ),
                        this.key("cipher").seq().obj(
                            this.key("id").objid(OID),
                            this.key("p").seq().obj(
                                this.key("iv").octstr(),
                                this.key("sbox").octstr()
                            )
                        )
                    )
                ),
                this.key("cryptData").octstr()
            );
        }),
        Attr: asn1.define('Attr', function() {
            this.seq().obj(
                this.key('id').objid(OID),
                this.key('kv').any()
            );
        }),
        Privkey: asn1.define('DstuPrivkey', function() {
            this.seq().obj(
                this.key('version').int(),
                this.key('priv0').seq().obj(
                    this.key('id').objid(OID),
                    this.key('p').seq().obj(
                        this.key('p').seq().obj(
                            this.key('p').seq().obj(
                                this.key('param_m').int(),
                                this.key('param_k1').int()
                            ),
                            this.key('param_a').int(),
                            this.key('param_b').octstr(), // inverted
                            this.key('order').int(),
                            this.key('bp').octstr()
                        ),
                        this.key('sbox').octstr()
                    )
                ),
                this.key('param_d').octstr(),
                this.key('attr').implicit(0).seqof(ob.Attr)
            );
        }),
        to_pem: function(b64) {
            return [PEM_KEY_B, b64, PEM_KEY_E].join('\n');
        },
        is_valid : function(indata) {
            return (indata[0] == 0x30) && ((indata[1] & 0x80) == 0x80);
        },
        iit_parse: function(data) {

            var asn1 = ob.StoreIIT.decode(data, 'der'), mac, pad;
            mac = asn1.cryptParam.cryptParam.mac;
            pad = asn1.cryptParam.cryptParam.pad;

            if(mac.length !== 4) {
                throw new Error("Invalid mac len " + mac.length);
            }
            if(pad.length >= 8) {
                throw new Error("Invalid pad len " + pad.length);
            }
            if(asn1.cryptParam.cryptType !== 'IIT Store') {
                throw new Error("Invalid storage type");
            }

            return {
                "format": "IIT",
                "mac": mac,
                "pad": pad,
                "body": asn1.cryptData,
            }
        },
        pbes2_parse: function(data) {
            var asn1 = ob.StorePBES2.decode(data, 'der'), iv, sbox, salt, iter;

            if(asn1.head.id !== 'PBES2') {
                throw new Error(asn1.head.id);
            }
            if(asn1.head.p.key.id !== 'PBKDF2') {
                throw new Error(asn1.head.p.key.id);
            }
            if(asn1.head.p.key.p.cipher.id != 'GOST_34311_HMAC') {
                throw new Error(asn1.head.p.key.p.cipher.id);
            }
            if(asn1.head.p.cipher.id != 'GOST_28147_CFB') {
                throw new Error(asn1.head.p.cipher.id);
            }
            iv = asn1.head.p.cipher.p.iv;
            sbox = asn1.head.p.cipher.p.sbox;
            salt = asn1.head.p.key.p.salt;
            iter = asn1.head.p.key.p.cycles;

            if( (iv.length != 8) || (sbox.length != 64) || (salt.length != 32)) {
                throw new Error("IV len: " + iv.length + ", S-BOX len: " + sbox.length + ", SALT len: " + salt.length);
            }
            return {
                "format": "PBES2",
                "iv": iv,
                "sbox": sbox,
                "salt": salt,
                "iters": iter,
                "body": asn1.cryptData,
            }
        },
        guess_parse: function(indata) {
            var data = indata, ret;
            data = new Buffer(indata, 'raw');

            try {
                return ob.iit_parse(data);
            } catch (e) {}
            try {
                return ob.pbes2_parse(data);
            } catch(e) {}
            priv = ob.Privkey.decode(data, 'der');
            return;
            throw new Error("Unknown format");
        },
    };
    return {
        "parse": ob.guess_parse,
        "to_pem": ob.to_pem,
        "is_valid": ob.is_valid
    }
}

module.exports = Keycoder
