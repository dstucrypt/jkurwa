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

describe('Keycoder', function () {
    var keycoder = jk.Keycoder();
    describe('#parse()', function() {
        it("should parse encrypted key in PEM format", function () {
            var der = keycoder.maybe_pem(PEM_KEY),
                key_store = keycoder.parse(der);
            assert.equal(key_store.format, 'PBES2');
        });
    });
});
