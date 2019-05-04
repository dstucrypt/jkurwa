/* eslint-env mocha */
const gost89 = require("gost89");
const assert = require("assert");
const fs = require("fs");
const jk = require("../lib");
const Message = require("../lib/models/Message");

describe("Box", () => {
  const algo = gost89.compat.algos();
  const data = Buffer.from("123");
  const sign = Buffer.from(
    "e45fe541d047ae546825f91db53906306024ad12fcbe8185b9fce2e615e52b2084dad217d37612ee8761da493db0c4570ac5d323c649b1c83093897536b23a5b",
    "hex"
  );
  const time = 1540236305;

  const cert = jk.Certificate.from_asn1(
    fs.readFileSync(`${__dirname}/data/SELF_SIGNED1.cer`)
  );
  const toCert = jk.Certificate.from_asn1(
    fs.readFileSync(`${__dirname}/data/SELF_SIGNED_ENC_40A0.cer`)
  );
  const priv = jk.Priv.from_asn1(
    fs.readFileSync(`${__dirname}/data/PRIV1.cer`),
  );
  const privEnc40A0 = jk.Priv.from_asn1(
    fs.readFileSync(`${__dirname}/data/Key40A0.cer`),
  );
  const privEncE54B = jk.Priv.from_asn1(
    fs.readFileSync(`${__dirname}/data/KeyE54B.cer`),
  );

  const box = new jk.Box({ algo });

  describe("transport", () => {
    const transport = fs.readFileSync(`${__dirname}/data/message.transport`);

    it("should parse transport buffer headers", () => {
      const {
        pipe: [head]
      } = box.unwrap(transport);
      assert.deepEqual(head, {
        transport: true,
        headers: {
          EDRPOU: "1234567891",
          RCV_EMAIL: "user@tax.mail.com",
          DOC_TYPE: "3"
        }
      });
    });

    it("should parse message from transport buffer", () => {
      const { content } = box.unwrap(transport);
      assert.deepEqual(content, Buffer.from('123', 'binary'));
    });
  });

  describe("signed p7s", () => {
    const p7s = fs.readFileSync(`${__dirname}/data/message.p7`);

    it("should parse buffer", () => {
      const { content } = box.unwrap(p7s);
      assert.deepEqual(content, Buffer.from('123', 'binary'));
    });

  });

  describe("encrypted p7s", () => {
    const p7s = fs.readFileSync(`${__dirname}/data/enc_message.p7`);

    it("should throw when key is not loaded into box", () => {
      assert.throws(
        ()=> box.unwrap(p7s),
        /No key-certificate pair found for given op encrypt and role /
      );
    });

    it("should throw if loaded key is marked as signature-only", () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({priv, cert});
      assert.throws(
        ()=> boxWithKey.unwrap(p7s),
        /No key-certificate pair found for given op encrypt and role /
      );

    });

    it("should return error if sender certificate is not found during lookup", () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({priv: privEnc40A0, cert: toCert});
      const {error} = boxWithKey.unwrap(p7s);
      assert.equal(error, 'ENOCERT');
    });

    it("should unwrap if both certificates are present", () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({priv: privEnc40A0, cert: toCert});
      boxWithKey.load({cert});
      const {content} = boxWithKey.unwrap(p7s);
      assert.deepEqual(content, Buffer.from('123'));
    });

  });

});
