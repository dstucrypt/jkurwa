var asn1 = require('asn1.js'),
    Big = require('./3rtparty/jsbn.packed.js'),
    rfc3280 = require('./rfc3280.js'),
    b64_decode = require('./base64.js').b64_decode,
    models = require('./lib/models/index.js'),
    util = require('./lib/util.js'),
    Buffer = require('buffer').Buffer;

var Keycoder = function() {

    var OID = {
        "1 3 6 1 4 1 19398 1 1 1 2": "IIT Store",
        '1 2 840 113549 1 5 13': "PBES2",
        "1 2 840 113549 1 5 12": "PBKDF2",
        '1 2 804 2 1 1 1 1 1 2': "GOST_34311_HMAC",
        '1 2 804 2 1 1 1 1 1 1 3': "GOST_28147_CFB",
        '1 2 804 2 1 1 1 1 3 1 1': "DSTU_4145_LE",
    };

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
        to_pem: function(b64, desc) {
            var begin, end;
            if(desc === undefined) {
                desc = 'PRIVATE KEY';
            }
            begin = '-----BEGIN ' + desc + '-----';
            end = '-----END ' + desc + '-----';

            return [begin, b64, end].join('\n');
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
        privkey_parse: function(data) {
            var priv = ob.Privkey.decode(data, 'der');
            return {
                param_d: new Big(util.add_zero(priv.param_d, true)),
                curve: {
                    m: priv.priv0.p.p.p.param_m,
                    k1: priv.priv0.p.p.p.param_k1,
                    a: new Big([priv.priv0.p.p.param_a]),
                    b: new Big(util.add_zero(priv.priv0.p.p.param_b, true)),
                    order: new Big(util.add_zero(priv.priv0.p.p.order)),
                    base: new Big(util.add_zero(priv.priv0.p.p.bp, true)),
                },
                sbox: priv.priv0.p.sbox,
                format: "privkey",
            }
        },
        cert_parse: function(data) {
            var cert = rfc3280.Certificate.decode(data, 'der');
            return new models.Certificate(cert);
        },
        is_pem: function(indata) {
            if(indata.constructor === Uint8Array) {
                if((indata[0] === 0x2D) &&
                   (indata[1] === 0x2D) &&
                   (indata[2] === 0x2D) &&
                   (indata[3] === 0x2D) &&
                   (indata[4] === 0x2D)) {
                    return true;
                }
            }
            if(typeof(indata) === 'string') {
                return indata.indexOf('-----') === 0;
            }
        },
        maybe_pem: function(indata) {
            var start, end, ln;

            if(ob.is_pem(indata) !== true) {
                return indata;
            }
            if(typeof(indata) !== 'string') {
                indata = String.fromCharCode.apply(null, indata);
            }
            indata = indata.split('\n');
            for(start=0; start<indata.length; start++) {
                ln = indata[start];
                if(ln.indexOf('-----')===0) {
                    start ++;
                    break;
                }
            }

            for(end=1; end<=indata.length; end++) {
                ln = indata[indata.length-end];
                if(ln.indexOf('-----')===0) {
                    break;
                }
            }

            indata = indata.slice(start, -end).join('');
            return b64_decode(indata);
        },
        guess_parse: function(indata) {
            var data, ret, tr;
            data = new Buffer(indata, 'raw');

            tr = [
                'iit_parse',
                'pbes2_parse',
                'privkey_parse',
                'cert_parse',
            ];

            for(var i=0; i<tr.length; i++) {
                try {
                    return ob[tr[i]](data);
                } catch (e) {}
            }

            throw new Error("Unknown format");
        },
    };
    return {
        "parse": ob.guess_parse,
        "to_pem": ob.to_pem,
        "is_valid": ob.is_valid,
        "maybe_pem": ob.maybe_pem,
    }
}

module.exports = Keycoder
