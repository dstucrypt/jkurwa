'use strict';

var assert = require("assert"),
    jk = require('../lib/index.js'),
    Field = jk.Field;


describe('API', function () {
    var curve = jk.std_curve('DSTU_PB_257'),
        expect_d = new jk.Field('40a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d', 'hex', curve),
        expect_pubx = new jk.Field('e54bf3f92a281d02f46ad5637387a8f13c9698816cb4f8beadfc0565fa63d6b0', 'hex', curve);

    describe('pkey()', function () {
        it('should create private key from string', function () {
            var priv = new jk.Priv(curve, new Field('40a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d', 'hex', curve));
            assert.equal(priv.type, 'Priv');
            assert.equal(priv.d.equals(expect_d), true);

            priv = curve.pkey('40a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d');
            assert.equal(priv.type, 'Priv');
            assert.equal(priv.d.equals(expect_d), true);

            priv = jk.pkey('DSTU_PB_257', '40a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d');
            assert.equal(priv.type, 'Priv');
            assert.equal(priv.d.equals(expect_d), true);
            assert.equal(curve, priv.curve);

        });
    });

    describe('pubkey()', function () {

        it('should create private key from hex string', function () {
            var pub = new jk.Pub(curve, curve.point('e54bf3f92a281d02f46ad5637387a8f13c9698816cb4f8beadfc0565fa63d6b1'));

            assert.equal(pub.type, 'Pub');
            assert.equal(pub.point.x.equals(expect_pubx), true);


            pub = curve.pubkey('e54bf3f92a281d02f46ad5637387a8f13c9698816cb4f8beadfc0565fa63d6b1');
            assert.equal(pub.type, 'Pub');
            assert.equal(pub.point.x.equals(expect_pubx), true);


        });
    });

    describe('curve_id()', function () {
        it('should return curve id as defined in z1399-12', function () {
            assert.equal(curve.curve_id(), 6);
            assert.equal(jk.std_curve('DSTU_PB_431').curve_id(), 9);
        });
    })
});
