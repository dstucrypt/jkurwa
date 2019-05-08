/* eslint-env mocha */
const assert = require("assert");
const fs = require("fs");

const jk = require("../lib/index.js");

const { Field } = jk;

describe("API", () => {
  const curve = jk.std_curve("DSTU_PB_257");

  const expectD = new jk.Field(
    "00a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d",
    "hex",
    curve
  );
  const expectD6929 = new jk.Field(
    "6929ac618d278e5a9aabe5e1daf6e7f21a712cc0451cf91525a20fb1f8dddd63",
    "hex",
    curve,
  );

  const expectD431 = new jk.Field(
    "e54bf3f92a281d02f46ad5637387a8f13c9698816cb440a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d",
    "hex",
    curve
  );

  const expectPubx = new jk.Field(
    "e54bf3f92a281d02f46ad5637387a8f13c9698816cb4f8beadfc0565fa63d6b0",
    "hex",
    curve
  );

  describe("pkey()", () => {
    it("should create private key from hex string through jk.Priv()", () => {
      const priv = new jk.Priv(
        curve,
        new Field(
          "a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d",
          "hex",
          curve
        )
      );
      assert.equal(priv.type, "Priv");
      assert.equal(priv.d.equals(expectD), true);
    });

    it("should create private key from hex string through curve.pkey()", () => {
      const priv = curve.pkey(
        "a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d"
      );
      assert.equal(priv.type, "Priv");
      assert.equal(priv.d.equals(expectD), true);
    });

    it("should read trinominal private key from asn1", () => {
      const priv = jk.Priv.from_asn1(
        fs.readFileSync(`${__dirname}/data/Key40A0.cer`)
      );
      assert.equal(priv.type, "Priv");
      assert.equal(priv.d.equals(expectD), true);
    });

    it("should read trinominal private key from pem", () => {
      const priv = jk.Priv.from_pem(
        fs.readFileSync(`${__dirname}/data/Key40A0.pem`)
      );
      assert.equal(priv.type, "Priv");
      assert.equal(priv.d.equals(expectD), true);
    });

    it("should read trinominal private key from asn1 (6929)", () => {
      const priv = jk.Priv.from_asn1(
        fs.readFileSync(`${__dirname}/data/Key6929.cer`)
      );
      assert.equal(priv.type, "Priv");
      assert.equal(priv.d.equals(expectD6929), true);
    });

    it("should serialize trinominal private key to asn1", () => {
      const priv = curve.pkey(
        "a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d"
      );
      assert.deepEqual(
        fs.readFileSync(`${__dirname}/data/Key40A0.cer`),
        priv.to_asn1()
      );
    });

    it("should serialize trinominal private key to pem", () => {
      const priv = curve.pkey(
        "a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d"
      );
      assert.deepEqual(
        priv.to_pem(),
        fs.readFileSync(`${__dirname}/data/Key40A0.pem`).toString(),
      );
    });

    it("should serialize pentanominal private key to asn1", () => {
      const curve431 = jk.std_curve("DSTU_PB_431");
      const priv = curve431.pkey(
        "e54bf3f92a281d02f46ad5637387a8f13c9698816cb440a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d"
      );
      assert.deepEqual(
        fs.readFileSync(`${__dirname}/data/KeyE54B.cer`),
        priv.to_asn1()
      );
    });

    it("should read pentanominal private key from asn1", () => {
      const priv = jk.Priv.from_asn1(
        fs.readFileSync(`${__dirname}/data/KeyE54B.cer`)
      );
      assert.equal(priv.type, "Priv");
      assert.equal(priv.d.equals(expectD431), true);
    });

    it("should create private key from hex string through jk.pkey()", () => {
      const priv = jk.pkey(
        "DSTU_PB_257",
        "a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d"
      );
      assert.equal(priv.type, "Priv");
      assert.equal(priv.d.equals(expectD), true);
      assert.equal(curve, priv.curve);
    });

    it("should create private key from u8 BE buffer through jk.pkey()", () => {
      const buffer = [
        10,
        14,
        20,
        0,
        0,
        30,
        9,
        27,
        22,
        1,
        1,
        21,
        15,
        27,
        30,
        15,
        29,
        20,
        19,
        14,
        28,
        11,
        7,
        1,
        29,
        18,
        10,
        4,
        18,
        12,
        4,
        29
      ];

      const priv = jk.pkey("DSTU_PB_257", buffer, "buf8");
      assert.equal(priv.type, "Priv");
      assert.equal(priv.d.equals(expectD), true);
      assert.equal(curve, priv.curve);
    });

    it("should create private key from u32 LE buffer through jk.pkey()", () => {
      const buffer = [
        0x120c041d,
        0x1d120a04,
        0x1c0b0701,
        0x1d14130e,
        0x0f1b1e0f,
        0x16010115,
        0x001e091b,
        0x0a0e1400,
      ];

      const priv = jk.pkey("DSTU_PB_257", buffer, "buf32");
      assert.equal(priv.type, "Priv");
      assert.equal(priv.d.equals(expectD), true);
      assert.equal(curve, priv.curve);
    });
  });

  describe("pubkey()", () => {
    it("should create public key from hex string through jk.Pub()", () => {
      const pub = new jk.Pub(
        curve,
        curve.point(
          "e54bf3f92a281d02f46ad5637387a8f13c9698816cb4f8beadfc0565fa63d6b1"
        )
      );

      assert.equal(pub.type, "Pub");
      assert.equal(pub.point.x.equals(expectPubx), true);
    });

    it("should create public key from hex string through curve.pubkey", () => {
      const pub = curve.pubkey(
        "e54bf3f92a281d02f46ad5637387a8f13c9698816cb4f8beadfc0565fa63d6b1"
      );
      assert.equal(pub.type, "Pub");
      assert.equal(pub.point.x.equals(expectPubx), true);
    });

    it("should create public key from hex string through jk.pubkey()", () => {
      const pub = jk.pubkey(
        "DSTU_PB_257",
        "e54bf3f92a281d02f46ad5637387a8f13c9698816cb4f8beadfc0565fa63d6b1"
      );
      assert.equal(pub.type, "Pub");
      assert.equal(pub.point.x.equals(expectPubx), true);
    });

    it("should create public key from u8 BE buffer through jk.pubkey()", () => {
      const pub = jk.pubkey(
        "DSTU_PB_257",
        [
          229,
          75,
          243,
          249,
          42,
          40,
          29,
          2,
          244,
          106,
          213,
          99,
          115,
          135,
          168,
          241,
          60,
          150,
          152,
          129,
          108,
          180,
          248,
          190,
          173,
          252,
          5,
          101,
          250,
          99,
          214,
          177
        ],
        "buf8"
      );
      assert.equal(pub.type, "Pub");
      assert.equal(pub.point.x.equals(expectPubx), true);
    });

    it("should create public key from u32 LE buffer through jk.pubkey()", () => {
      const pub = jk.pubkey(
        "DSTU_PB_257",
        [
          0xfa63d6b1,
          0xadfc0565,
          0x6cb4f8be,
          0x3c969881,
          0x7387a8f1,
          0xf46ad563,
          0x2a281d02,
          0xe54bf3f9
        ],
        "buf32"
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

  describe("equals()", () => {
    it("should return true if curves are same", () => {
      assert.equal(
        jk.std_curve("DSTU_PB_257").equals(jk.std_curve("DSTU_PB_257")),
        true
      );
    });

    it("should return false if curves are different", () => {
      assert.equal(
        jk.std_curve("DSTU_PB_257").equals(jk.std_curve("DSTU_PB_431")),
        false
      );
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
