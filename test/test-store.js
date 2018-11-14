'use strict';

var jk = require('../lib/index.js'),
    keys = require('./data/keys'),
    assert = require("assert");

describe('Keycoder', function () {
    var b257 = jk.std_curve('DSTU_PB_257'),
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
            var key_store = jk.guess_parse(keys.PEM_KEY_ENC);
            assert.equal(key_store.format, 'PBES2');
        });

        it("should parse raw key in PEM format", function () {
            var store = jk.guess_parse(keys.PEM_KEY_RAW),
                key;

            assert.equal(store.format, 'privkeys');
            check_257(store.keys[0]);
            check_431(store.keys[1]);

            key = jk.Priv.from_pem(keys.PEM_KEY_RAW);
            assert.equal(key.type, 'Priv');
            check_257(key);

            store = jk.Priv.from_pem(keys.PEM_KEY_RAW, true);
            assert.equal(store.format, 'privkeys');
            check_257(store.keys[0]);
            check_431(store.keys[1]);
        })
    });
});
