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
    var keycoder = new jk.Keycoder(),
        b257 = jk.std_curve('DSTU_PB_257'),
        b431 = jk.std_curve('DSTU_PB_431');

    var check_257 = function (key) {
        assert.equal(key.type, 'Priv');

        assert.equal(key.d.toString(true), '1111111111111111111111111111111111111111111111111111111111111111');

        assert.equal(b257.equals(key.curve), true);
    };

    var check_431 = function (key) {

        assert.equal(key.type, 'Priv');
        assert.equal(key.d.toString(true), '888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888');

        assert.equal(b431.equals(key.curve), true);
    };

    describe('#parse()', function() {
        it("should parse encrypted key in PEM format", function () {
            var der = keycoder.maybe_pem(PEM_KEY),
                key_store = keycoder.parse(der);
            assert.equal(key_store.format, 'PBES2');
        });

        it("should parse raw key in PEM format", function () {
            var der = keycoder.maybe_pem(PEM_KEY2),
                store = keycoder.parse(der);

            assert.equal(store.format, 'privkeys')
            check_257(store.keys[0]);
            check_431(store.keys[1]);

            store = jk.Priv.from_asn1(der);
            assert.equal(store.format, 'privkeys')
            check_257(store.keys[0]);
            check_431(store.keys[1]);
        })
    });
});
