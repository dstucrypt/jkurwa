var wnaf = require('../lib/wnaf/index.js'),
    assert = require("assert"),
    Curve = require('../curve.js'),
    gf2m = require('../lib/gf2m.js'),
    Big = Curve.Big;

describe('WNAF', function() {
    var curve = Curve.defined.DSTU_B_257;

    var bigi = new Big("5679ed8f04c3e40b463762e9c66e7c26bc795713c3018dd6c572261df82fcdda", 16);
    var point_x = new Big("1a77131a7c14f9aa6ea8c760d39673d5f0330fab1118d55b55b7af0735975485f", 16);
    var point_y = new Big("dc058ada665d99084038b5f914fb9cf7214760a4865b49caf7f4be7379f3a395", 16);
    var point = curve.point(point_x, point_y);

    var expect_bigi_wnaf = [
        851969, -589820, -196603, 196615, -65530,
        983045, -851961, 589828, -589819, 196612,
        -327676, -327676, 458757, 196613, 196616,
        983045, -983035, 720902, -458748, -458746,
        -327674, 327684, -65530, -196604, 458756,
        196612, 458756, -196604, 196612, -327676,
        458757, 196613, 851972, 65540, -458746,
        -983033, 327685, 983047, -327674, -65532,
        -196604, 851973, 327684
    ];

    var expect_bigi_naf = [
            65537, -65535, -65535, -65533, 65538, -65535, -65531,
            65537, -65532, -65531, 65539, -65533, 65537, 65537,
            65539, -65534, -65534, -65535, 65537, -65534, -65535,
            -65534, -65535, -65533, 65538, -65534, 65537, -65530,
            65537, -65533, 65539, 65537, -65533, -65534, -65535,
            -65535, 65537, -65535, 65539, -65534, -65533, -65535,
            65538, 65537, -65532, 65540, -65535, -65534, 65538,
            -65535, 65537, -65534, 65538, 65537, -65535, -65534,
            65537, -65534, -65535, -65533, 65538, -65534, 65537,
            65538, -65535, -65535, 65537, 65541, -65534, 65540,
            -65533, 65537, 65537, -65531, 65539, -65534, -65535,
            -65534, 65540, -65535, 65539, -65535, -65535, -65535,
            65537,
    ];

    describe("#getWindowSize()", function() {

        it("should compute window size of bigint", function() {
            var width = wnaf.getWindowSize(bigi.bitLength());

            assert.equal(5, width);
        })

    });

    describe("#precomp()", function() {
        it("should generate precomputations for given point", function() {
            var precomps = wnaf.precomp(point, 5);

            assert.equal(precomps.pos.length, 8);
            assert.equal(precomps.neg.length, 8);

            for (var i=0; i < 8; i++) {
                var expect_pt = point.mul(new Big([1 + i + i]));
                assert.equal(true, precomps.pos[i].equals(expect_pt));
                assert.equal(true, precomps.neg[i].equals(expect_pt.negate()));
            };
        })
    });

    describe("#windowNaf()", function() {
        it("should compute wnaf for given big number", function() {
            var width = wnaf.getWindowSize(bigi.bitLength());
            var bigi_wnaf = wnaf.windowNaf(width, bigi);

            assert.equal(43, bigi_wnaf.length);
            for(var i=0; i<bigi_wnaf.length; i++) {
                assert.equal(bigi_wnaf[i], expect_bigi_wnaf[i]);
            }
        })
    });

    describe("#compactNaf()", function() {
        it("should compute naf for given big number", function() {
            var bigi_naf = wnaf.compactNaf(bigi);

            assert.equal(85, bigi_naf.length);

            for(var i=0; i<bigi_naf.length; i++) {
                assert.equal(bigi_naf[i], expect_bigi_naf[i]);
            }
        })
    });

    describe("#twice()", function() {
        it("should add point to itself", function() {
            var pt1 = point;
            for(i=0; i<500; i++) {
                pt1.twice();
            }
        });
    });

    describe("#mulPos()", function() {
        it("should multiplicate point using wnaf function", function() {
            var bigi = new Big("9", 16);
            console.log("bigi " + bigi.toString(16));
/*
            var mul_point = point.mul(bigi);
            var mul_point_wnaf = wnaf.mulPos(point, bigi);
*/
            //console.log("regular mul: " +  mul_point.toString(16));
            //console.log("wnaf mul: " +  mul_point_wnaf.toString(16));

            //assert.equal(true, mul_point.equals(mul_point_wnaf));

        });
    });

})
