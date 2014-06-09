'use strict';

var jk = require('../lib/index.js'),
    assert = require("assert");

var PEM_KEY = '-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
        'MIIBqjCBsAYJKoZIhvcNAQUNMIGiMEMGCSqGSIb3DQEFDDA2BCAxpY3BRimBGJz2' +
        'xwHidsdVOlq19uNthBjkqkDJMM84dgICJxAwDgYKKoYkAgEBAQEBAgUAMFsGCyqG' +
        'JAIBAQEBAQEDMEwECEuxD1wpRdSeBECp1utF8TxwgoDElnsjH16t9ljrpMA3KR04' +
        '2WvwJcpOF/jpcg3GFbQ6KJdfC8Heo2Q4tWTqLBef0BI+bbj6xXkEBIH0KaIuKVHm' +
        'MuHkRK449SHIkP9jd/wFORE6ZnIL/E6RB8VmoH4+q5rmfzN+2cZsAhNj55UIqf36' +
        'CeeId9++dlQxYNyDGVQnqcf/L29A2ND+omWDxy725eIEXalRKmH7wrlXPosL3I8D' +
        'TYzaOspjt4yYd/p1wih1a+dgg6I1JHoJTB7ymW/7/LRebRSAezjiaoYmEDUTHexj' +
        's3MHtE7ywOr+UTks2KK4tQ/G+LyLGmLv0nbU6BuzWPSTG6qjZgwMC131LlIz2Q0f' +
        'TvUgPEDwNs9ZEpFGYL8oISybP9kUHLibk8E1It6zMIWiXMECtbfbo3cHimReiA==\n' +
        '-----END ENCRYPTED PRIVATE KEY-----';

var PEM_KEY2 = '-----BEGIN PRIVATE KEY-----\n' +
'MIIDiAIBADCByQYLKoYkAgEBAQEDAQEwgbkwdTAHAgIBAQIBDAIBAAQhEL7j22rq' +
'nh+GV4xFwSWU/5QjlKfXOPkYfmUVAXKU9M4BAiEAgAAAAAAAAAAAAAAAAAAAAGdZ' +
'ITrxgumH0+F3FJB9Rw0EIbYP0tjc6Kk0I8YQG8qRxHoAfmwwCybNVWybDn0g7ykq' +
'AARAqdbrRfE8cIKAxJZ7Ix9erfZY66TANykdONlr8CXKThf46XINxhW0OiiXXwvB' +
'3qNkOLVk6iwXn9ASPm24+sV5BAQgERERERERERERERERERERERERERERERERERER' +
'ERERERGgggKTMDIGDCsGAQQBgZdGAQECATEiBCARERERERERERERERERERERERER' +
'ERERERERERERERERETAyBgwrBgEEAYGXRgEBAgUxIgQgERERERERERERERERERER' +
'EREREREREREREREREREREcAwSQYMKwYBBAGBl0YBAQIDMTkDNwMRERERERERERER' +
'EREREREREREREREREREREREREREREREREREREREREREREREREREREREREREwggFZ' +
'BgwrBgEEAYGXRgEBAgIxggFHMIIBQzCBvDAPAgIBrzAJAgEFAgEDAgEBAgEBBDYD' +
'zhBJD2pwj8Jt/ow9J8T5TmkBNNW/+YjY0oqurt6XWTbGa6xTaxiuLcMSykkxF9qk' +
'acZAyvMCNj///////////////////////////////////7oxdUWACajApyTwL4Gq' +
'ih/Lr4DZDHqVEQUEzwQ2GmK6edmBM6Fruuftmo4Dwy4IJNV673L4iYaHTlquScJ7' +
'7UmiqVBYBoQmwhcemf07Q8WUfIV8BECp1utF8TxwgoDElnsjH16t9ljrpMA3KR04' +
'2WvwJcpOF/jpcg3GFbQ6KJdfC8Heo2Q4tWTqLBef0BI+bbj6xXkEBECp1utF8Txw' +
'goDElnsjH16t9ljrpMA3KR042WvwJcpOF/jpcg3GFbQ6KJdfC8Heo2Q4tWTqLBef' +
'0BI+bbj6xXkEMIGABgwrBgEEAYGXRgEBAgYxcDBuBEARERERERERERERERERERER' +
'ERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERER' +
'BAgREREREREREQQgERERERERERERERERERERERERERERERERERERERERERE=\n' +
'-----END PRIVATE KEY-----' ;

describe('Keycoder', function () {
    var keycoder = new jk.Keycoder();
    var base_257 = new jk.Big('2a29ef207d0e9b6c55cd260b306c7e007ac491ca1b10c62334a9e8dcd8d20fb6', 16);
    describe('#parse()', function() {
        it("should parse encrypted key in PEM format", function () {
            var der = keycoder.maybe_pem(PEM_KEY),
                key_store = keycoder.parse(der);
            assert.equal(key_store.format, 'PBES2');
        });

        it("should parse raw key in PEM format", function () {
            var der = keycoder.maybe_pem(PEM_KEY2),
                keys = keycoder.parse(der),
                key1 = keys.keys[0],
                key2 = keys.keys[1];

            assert.equal(keys.format, 'privkeys')
            assert.equal(key1.format, 'privkey')
            assert.equal(key1.curve.m, 257);
            assert.equal(key1.curve.k1, 12);
            assert.equal(key1.curve.a.toString(16), '0');
            assert.equal(key1.curve.b.toString(16), '1cef494720115657e18f938d7a7942394ff9425c1458c57861f9eea6adbe3be10');
            assert.equal(key1.curve.order.toString(16), '800000000000000000000000000000006759213af182e987d3e17714907d470d');
            assert.equal(key1.curve.base.toString(16), '2a29ef207d0e9b6c55cd260b306c7e007ac491ca1b10c62334a9e8dcd8d20fb6');
            assert.equal(key1.param_d.toString(16), '1111111111111111111111111111111111111111111111111111111111111111');

            assert.equal(key2.format, 'privkey')
            assert.equal(key2.curve.m, 431);
            assert.equal(key2.curve.ks.toString(), [5, 3, 1]);
            assert.equal(key2.curve.a.toString(16), '1');
            assert.equal(key2.curve.b.toString(16), '3ce10490f6a708fc26dfe8c3d27c4f94e690134d5bff988d8d28aaeaede975936c66bac536b18ae2dc312ca493117daa469c640caf3');
            assert.equal(key2.curve.order.toString(16), '3fffffffffffffffffffffffffffffffffffffffffffffffffffffba3175458009a8c0a724f02f81aa8a1fcbaf80d90c7a95110504cf');
            assert.equal(key2.curve.base.toString(16), '1a62ba79d98133a16bbae7ed9a8e03c32e0824d57aef72f88986874e5aae49c27bed49a2a95058068426c2171e99fd3b43c5947c857c');
            assert.equal(key2.param_d.toString(16), '888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888');

        })
    });
});
