/* eslint-env mocha */
const assert = require("assert");

const jk = require("../lib/index.js");

const { Field } = jk;

describe("API", () => {
  const curve = jk.std_curve("DSTU_PB_257");

  const expectD = new jk.Field(
    "40a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d",
    "hex",
    curve
  );

  const expectPubx = new jk.Field(
    "e54bf3f92a281d02f46ad5637387a8f13c9698816cb4f8beadfc0565fa63d6b0",
    "hex",
    curve
  );

  describe("pkey()", () => {
    it("should create private key from string", () => {
      let priv = new jk.Priv(
        curve,
        new Field(
          "40a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d",
          "hex",
          curve
        )
      );
      assert.equal(priv.type, "Priv");
      assert.equal(priv.d.equals(expectD), true);

      priv = curve.pkey(
        "40a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d"
      );
      assert.equal(priv.type, "Priv");
      assert.equal(priv.d.equals(expectD), true);

      priv = jk.pkey(
        "DSTU_PB_257",
        "40a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d"
      );
      assert.equal(priv.type, "Priv");
      assert.equal(priv.d.equals(expectD), true);
      assert.equal(curve, priv.curve);
    });
  });

  describe("pubkey()", () => {
    it("should create private key from hex string", () => {
      let pub = new jk.Pub(
        curve,
        curve.point(
          "e54bf3f92a281d02f46ad5637387a8f13c9698816cb4f8beadfc0565fa63d6b1"
        )
      );

      assert.equal(pub.type, "Pub");
      assert.equal(pub.point.x.equals(expectPubx), true);

      pub = curve.pubkey(
        "e54bf3f92a281d02f46ad5637387a8f13c9698816cb4f8beadfc0565fa63d6b1"
      );
      assert.equal(pub.type, "Pub");
      assert.equal(pub.point.x.equals(expectPubx), true);
    });
  });

  describe("curve_id()", () => {
    it("should return curve id as defined in z1399-12", () => {
      assert.equal(curve.curve_id(), 6);
      assert.equal(jk.std_curve("DSTU_PB_431").curve_id(), 9);
    });
  });

  describe("std_curve()", () => {
    it("should known standard curve PB 257", () => {
      jk.std_curve("DSTU_PB_257");
    });

    it("should known standard curve PB 431", () => {
      jk.std_curve("DSTU_PB_257");
    });

    it("should throw when unknown curve is asked for", () => {
      assert.throws(
        () => {
          jk.std_curve("DSTU_PB_255");
        },
        Error,
        "Curve with such name was not defined"
      );
    });
  });
});
