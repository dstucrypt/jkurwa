/* eslint-env mocha */
/* global window,document,crypto */
const valueHEX =
  "aff3ee09cb429284985849e20de5742e194aa631490f62ba88702505629a65890";

const rvHEX =
  "ff3ee09cb429284985849e20de5742e194aa631490f62ba88702505629a60895";

/* eslint-disable no-global-assign, no-unused-expressions */
try {
  window.location;
  document.body;
} catch (e) {
  window = {};
  document = {
    attachEvent() {}
  };
}

try {
  crypto.getRandomValues;
} catch (e) {
  crypto = {
    // Moch random only for testing purposes.
    // SHOULD NOT BE USED IN REAL CODE.
    getRandomValues(buf) {
      /* eslint-disable no-param-reassign, no-bitwise */
      for (let i = 0; i < buf.length; i+=1) {
        buf[i] = Math.random() * 255;
        buf[i] |= (Math.random() * 255) << 8;
        buf[i] |= (Math.random() * 255) << 16;
        buf[i] |= (Math.random() * 255) << 24;
      }
      /* eslint-enable no-param-reassign, no-bitwise */
      return buf;
    }
  };
}
/* eslint-enable no-global-assign, no-unused-expressions */

const assert = require("assert");

const jk = require("../lib/index.js");

const { Field, Priv, Pub } = jk;

describe("Curve", () => {
  describe("#comp_modulus()", () => {
    it("should compute curve modulus", () => {
      const curve = jk.std_curve("DSTU_PB_257");

      const modHEX =
        "20000000000000000000000000000000000000000000000000000000000001001";

      const mod = new Field(modHEX, "hex", curve);
      const modulus = curve.comp_modulus(257, [12, 0]);
      assert.equal(mod.equals(modulus), true);
      assert.equal(curve.modulus.bitLength(), 258);
    });

    it("should not change modulus value on curve", () => {
      const curve = jk.std_curve("DSTU_PB_257");

      const modHEX =
        "20000000000000000000000000000000000000000000000000000000000001003";

      const mod = new Field(modHEX, "hex", curve);

      const modBefore = curve.modulus;
      const modulus = curve.comp_modulus(257, [12, 1]);

      assert.equal(true, mod.equals(modulus));
      assert.equal(258, curve.modulus.bitLength());
      assert.equal(modBefore.equals(curve.modulus), true);
      assert.equal(mod.equals(curve.modulus), false);
    });
  });
  describe("#contains", () => {
    const curve = jk.std_curve("DSTU_PB_257");

    const pubX = new Field(
      "00AFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A6589",
      "hex",
      curve
    );

    const pubY = new Field(
      "01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C",
      "hex",
      curve
    );

    it("should check if point is part of curve", () => {
      const pubQ = curve.point(pubX, pubY);
      assert.equal(curve.contains(pubQ), true);
    });
  });

  describe("#generate()", () => {
    it("should generate new private key with pubkey on curve", () => {
      const curve = jk.std_curve("DSTU_PB_257");
      const priv = curve.keygen();
      const pub = priv.pub();
      assert.equal(true, curve.contains(pub.point));
    });
  });
});

describe("Field", () => {
  const curve = jk.std_curve("DSTU_PB_257");

  describe("#mod", () => {
    it("should return mod of value", () => {
      const valueA = new Field(valueHEX, "hex", curve);
      const expectB = new Field(rvHEX, "hex", curve);
      const fieldA = curve.field(valueA);
      assert.equal(true, fieldA.equals(expectB));
    });
  });

  describe("#mul", () => {
    it("should return product of two values", () => {
      const hexB =
        "01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C";
      const expectHEX =
        "157b8e91c8b225469821fc836045a7c09c30d9fdee54b680c8247821f8c4e3352";
      const valueA = new Field(valueHEX, "hex", curve);
      const valueB = new Field(hexB, "hex", curve);
      const expectC = new Field(expectHEX, "hex", curve);

      const fieldA = curve.field(valueA);
      const valueC = fieldA.mod_mul(valueB);

      assert.equal(true, valueC.equals(expectC));
    });
  });

  describe("#inv", () => {
    it("should return negative of r", () => {
      const expectRHEX =
        "f5ae84d0c4dc2e7e89c670fb2083d124be50b413efb6863705bd63a5168352e0";
      const valueA = new Field(valueHEX, "hex", curve);
      const expectR = new Field(expectRHEX, "hex", curve);
      const fieldA = curve.field(valueA);
      const valueR = fieldA.invert();

      assert.equal(true, valueR.equals(expectR));
    });
  });

  describe("#shiftRightM", () => {
    it("should bitshift big integer rightwise inplace", () => {
      const initial = new Field(
        "7a32849e569c8888f25de6f69a839d75057383f473acf559abd3c5d683294ceb",
        "hex",
        curve
      );
      const expect = new Field(
        "3d19424f2b4e4444792ef37b4d41ceba82b9c1fa39d67aacd5e9e2eb4194a67",
        "hex",
        curve
      );
      initial.shiftRightM(5);

      assert.equal(initial.equals(expect), true);
    });
  });
});

describe("Point", () => {
  const curve = jk.std_curve("DSTU_PB_257");

  const RAND_E_HEX =
    "7A32849E569C8888F25DE6F69A839D75057383F473ACF559ABD3C5D683294CEB";

  const PUB_X_HEX =
    "00AFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A6589";

  const PUB_Y_HEX =
    "01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C";

  describe("#add", () => {
    it("should produce specific point", () => {
      const pubX = new Field(PUB_X_HEX, "hex", curve);

      const pubY = new Field(PUB_Y_HEX, "hex", curve);

      const ppX = new Field(
        "176dbde19773dfd335665597e8d6a0ab678721a5bb7030f25dc4c48b809ef3520",
        "hex",
        curve
      );

      const ppY = new Field(
        "6e75301556ea5d571403086691030f024c026907c8e818b2eedd9184d12040ee",
        "hex",
        curve
      );

      const pubQ = curve.point(pubX, pubY);
      const pub2Q = pubQ.add(pubQ);

      assert.equal(pub2Q.x.equals(ppX), true);
      assert.equal(pub2Q.y.equals(ppY), true);
    });
  });

  describe("#mul", () => {
    it("should produce specific point", () => {
      const randE = new Field(RAND_E_HEX, "hex", curve);

      const pubX = new Field(PUB_X_HEX, "hex", curve);

      const pubY = new Field(PUB_Y_HEX, "hex", curve);

      const ppX = new Field(
        "f26df77ca4c807c6b94f5c577415a1fce603a85ae7678717e16cb9a78de32d15",
        "hex",
        curve
      );

      const ppY = new Field(
        "1785fded2804bea15b02c4fd785fd3e98ab2435b8d78da44e195a9a088d3fc2d4",
        "hex",
        curve
      );

      const pubQ = curve.point(pubX, pubY);
      const point = pubQ.mul(randE);

      assert.equal(point.x.equals(ppX), true);
      assert.equal(point.y.equals(ppY), true);
    });
  });

  describe("#trace()", () => {
    it("should compute field trace", () => {
      const valueHex =
        "2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6";
      const value = new Field(valueHex, "hex", curve);
      const trace = value.trace();

      assert.equal(trace, 1);
    });
  });

  describe("#expand()", () => {
    it("should compute coordinates from compressed point (zero)", () => {
      const coords = curve.expand(new Field([0], "buf8", curve));
      assert.equal(coords.x.is_zero(), true);
    });

    it("should compute coordinates from compressed point", () => {
      const coords = curve.expand(
        "2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6"
      );

      assert.equal(true, curve.base.equals(coords));

      const pt = curve.point(
        "2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6"
      );
      assert.equal(true, pt.equals(curve.base));
    });

    it("should check tax office pubkey decompression (1)", () => {
      const compressed = new Field(
        "01A77131A7C14F9AA6EA8C760D39673D5F0330FAB1118D55B55B7AF0735975485F",
        "hex",
        curve
      );
      const pt = curve.point(compressed);
      const expectPoint = curve.point(
        new Field(
          "01A77131A7C14F9AA6EA8C760D39673D5F0330FAB1118D55B55B7AF0735975485F",
          "hex",
          curve
        ),
        new Field(
          "DC058ADA665D99084038B5F914FB9CF7214760A4865B49CAF7F4BE7379F3A395",
          "hex",
          curve
        )
      );

      assert.equal(pt.equals(expectPoint), true);
    });

    it("should check tax office pubkey decompression (2)", () => {
      const compressed = new Field(
        "2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB6",
        "hex",
        curve
      );
      const pt = curve.point(compressed);
      const expectPoint = curve.point(
        new Field(
          "2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7",
          "hex",
          curve
        ),
        new Field(
          "010686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF",
          "hex",
          curve
        )
      );

      assert.equal(pt.equals(expectPoint), true);
    });
  });

  describe("#compress()", () => {
    it("should compress point coords", () => {
      const pt = curve.base;
      const compressed = pt.compress();

      const expected = new Field(
        "2a29ef207d0e9b6c55cd260b306c7e007ac491ca1b10c62334a9e8dcd8d20fb6",
        "hex",
        curve
      );

      assert.equal(compressed.equals(expected), true);
    });
  });

  describe("#toString()", () => {
    it("should print points nicely", () => {
      const pubX = new Field(PUB_X_HEX, "hex", curve);
      const pubY = new Field(PUB_Y_HEX, "hex", curve);
      const x = PUB_X_HEX.slice(2).toLowerCase();
      const y = PUB_Y_HEX.slice(1).toLowerCase();

      const point = curve.point(pubX, pubY);
      assert.equal(point.toString(), `<Point x:<Field ${x}>, y:<Field ${y}> >`);
    });
  });
});

describe("Sign", () => {
  const curve = jk.std_curve("DSTU_PB_257");

  const privD = new Field(
    "2A45EAFE4CD469F811737780C57253360FBCC58E134C9A1FDCD10B0E4529A143",
    "hex",
    curve
  );

  const hashValue = new Field(
    "6845214B63288A832A772E1FE6CB6C7D3528569E29A8B3584370FDC65F474242",
    "hex",
    curve
  );

  const hashBuffer = Buffer.from(
    "6845214B63288A832A772E1FE6CB6C7D3528569E29A8B3584370FDC65F474242",
    "hex"
  );

  const randE = new Field(
    "7A32849E569C8888F25DE6F69A839D75057383F473ACF559ABD3C5D683294CEB",
    "hex",
    curve
  );

  const pubX = new Field(
    "00AFF3EE09CB429284985849E20DE5742E194AA631490F62BA88702505629A6589",
    "hex",
    curve
  );

  const pubY = new Field(
    "01B345BC134F27DA251EDFAE97B3F306B4E8B8CB9CF86D8651E4FB301EF8E1239C",
    "hex",
    curve
  );

  describe("#help_sign", () => {
    it("should sign long binary value with privkey and provided E", () => {
      const priv = new Priv(curve, privD);
      const sig = priv.help_sign(hashValue, randE);

      assert.equal(
        sig.s.toString(true),
        "ccc6816453a903a1b641df999011177df420d21a72236d798532aef42e224ab"
      );
      assert.equal(
        sig.r.toString(true),
        "491fa1ef75eaef75e1f20cf3918993ab37e06005ea8e204bc009a1fa61bb0fb2"
      );
    });
  });

  describe("#sign", () => {
    it("should sign long binary value with privkey and generated E", () => {
      const priv = new Priv(curve, privD);
      const sig = priv.sign(hashBuffer);

      assert.equal(Object.keys(sig).length, 3);
    });

    it("should return buffer with asn1 string", () => {
      const priv = new Priv(curve, privD);
      const sig = priv.sign(hashBuffer, "short");

      assert.equal(sig.length, 66);
      assert.equal(sig[0], 4);
      assert.equal(sig[1], 64);
    });
  });

  describe("#verify", () => {
    const signHex =
      "044091d08086a623d7fc292418636f634e82e52f8f989d423dae6c64878699cc2f11d0332bfe45c237421a41c2eb99e230f2629881c8e0c90be88610880e8c269d23";
    it("should parse asn1 signature", () => {
      const priv = new Priv(curve, privD);

      const pub = priv.pub();
      const ok = pub.verify(hashBuffer, Buffer.from(signHex, "hex"), "short");
      assert.equal(ok, true);
    });
  });

  describe("#pub", () => {
    it("should return pubkey from priv", () => {
      const priv = new Priv(curve, privD);

      const pub = priv.pub();

      assert.equal(pub.x.equals(pubX), true);
      assert.equal(pub.y.equals(pubY), true);

      const sig = priv.help_sign(hashValue, randE);
      const ok = pub.help_verify(hashValue, sig.s, sig.r);
      assert.equal(ok, true);
    });
  });

  describe("sign_serialise()", () => {
    it("Should return asn1 string", () => {
      const hex =
        "0440b20fbb61faa109c04b208eea0560e037ab938991f30cf2e175efea75efa11f49ab24e242ef2a5398d73622a7210d42df77110199f91d641b3a903a451668cc0c";
      const sign = {
        s: new Field(
          "ccc6816453a903a1b641df999011177df420d21a72236d798532aef42e224ab",
          "hex",
          curve
        ),
        r: new Field(
          "491fa1ef75eaef75e1f20cf3918993ab37e06005ea8e204bc009a1fa61bb0fb2",
          "hex",
          curve
        )
      };
      const asign = Priv.sign_serialise(sign, "short");
      assert.equal(asign.toString("hex"), hex);
    });
  });

  describe("parse_sign()", () => {
    it("Should parse asn1 string to {s, r} object", () => {
      const hex =
        "0440b20fbb61faa109c04b208eea0560e037ab938991f30cf2e175efea75efa11f49ab24e242ef2a5398d73622a7210d42df77110199f91d641b3a903a451668cc0c";

      const sign = {
        s: "ccc6816453a903a1b641df999011177df420d21a72236d798532aef42e224ab",
        r: "491fa1ef75eaef75e1f20cf3918993ab37e06005ea8e204bc009a1fa61bb0fb2"
      };
      const asign = Pub.parse_sign(Buffer.from(hex, "hex"), "short", curve);

      assert.equal(asign.s.toString(true), sign.s);
      assert.equal(asign.r.toString(true), sign.r);
    });
  });
});

describe("Broken", () => {
  const curve = jk.std_curve("DSTU_PB_257");

  describe("#expand()", () => {
    it("should compute coordinates from specific point", () => {
      const compressed = new Field(
        "76cd4555ad63455529755e5c3f3066c3bcb957cc63d00e22c6dd1e9ed316b419",
        "hex",
        curve
      );

      const coords = curve.expand(compressed);

      const px = new Field(
        "76cd4555ad63455529755e5c3f3066c3bcb957cc63d00e22c6dd1e9ed316b418",
        "hex",
        curve
      );
      const py = new Field(
        "12b20103548f45dcbed5486022dfcb244b2d996e0d3d761abaf73ba16ea26e0d3",
        "hex",
        curve
      );
      const expectPoint = curve.point(px, py);

      assert.equal(true, expectPoint.equals(coords));
    });
  });
});
