/* eslint-env mocha */
const gost89 = require("gost89");
const assert = require("assert");
const fs = require("fs");
const jk = require("../lib");

describe("Box", () => {
  const algo = gost89.compat.algos();

  const cert = jk.Certificate.from_asn1(
    fs.readFileSync(`${__dirname}/data/SELF_SIGNED1.cer`)
  );
  const toCert = jk.Certificate.from_asn1(
    fs.readFileSync(`${__dirname}/data/SELF_SIGNED_ENC_40A0.cer`)
  );
  const certE54B = jk.Certificate.from_asn1(
    fs.readFileSync(`${__dirname}/data/SELF_SIGNED_ENC_E54B.cer`)
  );
  const priv = jk.Priv.from_asn1(
    fs.readFileSync(`${__dirname}/data/PRIV1.cer`)
  );
  const privEnc40A0 = jk.Priv.from_asn1(
    fs.readFileSync(`${__dirname}/data/Key40A0.cer`)
  );
  const privEncE54B = jk.Priv.from_asn1(
    fs.readFileSync(`${__dirname}/data/KeyE54B.cer`)
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
      assert.deepEqual(content, Buffer.from("123", "binary"));
    });
  });

  describe("signed p7s", () => {
    const p7s = fs.readFileSync(`${__dirname}/data/message.p7`);

    it("should return signed content", () => {
      const { content } = box.unwrap(p7s);
      assert.deepEqual(content, Buffer.from("123", "binary"));
    });
  });

  describe("detached sign p7s", () => {
    const p7s = fs.readFileSync(`${__dirname}/data/message_detached.p7`);

    it("should report error if message is no supplied", () => {
      const { content, error } = box.unwrap(p7s);
      assert.deepEqual(error, "ENODATA");
      assert.deepEqual(content, p7s);
    });

    it("should return signed content if supplied separately", () => {
      const detachedContent = Buffer.from("123");
      const { content, error } = box.unwrap(p7s, detachedContent);
      assert.equal(error, null);
      assert.deepEqual(content, detachedContent);
    });

    it("should return error if detached content does not match signature", () => {
      const detachedContent = Buffer.from("1234");
      const { content, error } = box.unwrap(p7s, detachedContent);
      assert.deepEqual(error, "ESIGN");
      assert.deepEqual(content, p7s);
    });
  });

  describe("encrypted p7s", () => {
    const p7s = fs.readFileSync(`${__dirname}/data/enc_message.p7`);

    it("should throw when key is not loaded into box", () => {
      const { error } = box.unwrap(p7s);
      assert.equal(error, "ENOKEY");
    });

    it("should throw if loaded key is marked as signature-only", () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv, cert });
      const { error } = boxWithKey.unwrap(p7s);
      assert.equal(error, "ENOKEY");
    });

    it("should return error if sender certificate is not found during lookup", () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv: privEnc40A0, cert: toCert });
      const { error } = boxWithKey.unwrap(p7s);
      assert.equal(error, "ENOCERT");
    });

    it("should return ENOKEY if encryption certificate found, but has no matching key", () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv: privEncE54B, cert: toCert });
      boxWithKey.load({ cert });
      const { error } = boxWithKey.unwrap(p7s);
      assert.equal(error, "ENOKEY");
    });

    it("should throw mismatch error if KEK checksum fails for found key", () => {
      /* This test deliberately confuses library by creating serial number
       * collision and supplying matching certificate with wrong key
       * This error is not a part of normal operation. */
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv: privEncE54B, cert: certE54B });
      boxWithKey.load({ cert });
      assert.throws(
        () => boxWithKey.unwrap(p7s),
        /Key unwrap failed. Checksum mismatch/
      );
    });

    it("should not attemtp to recover from serial key collision if other matching certificate is also available", () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv: privEncE54B, cert: certE54B });
      boxWithKey.load({ priv: privEnc40A0, cert: toCert });
      boxWithKey.load({ cert });
      assert.throws(
        () => boxWithKey.unwrap(p7s),
        /Key unwrap failed. Checksum mismatch/
      );
    });

    it("should unwrap be okay if right certificate is before wrong one (collision)", () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv: privEnc40A0, cert: toCert });
      boxWithKey.load({ priv: privEncE54B, cert: certE54B });
      boxWithKey.load({ cert });
      const { content } = boxWithKey.unwrap(p7s);
      assert.deepEqual(content, Buffer.from("123"));
    });

    it("should unwrap if both certificates are present", () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv: privEnc40A0, cert: toCert });
      boxWithKey.load({ cert });
      const { content } = boxWithKey.unwrap(p7s);
      assert.deepEqual(content, Buffer.from("123"));
    });
  });

  describe("encrypted transport", () => {
    const p7s = fs.readFileSync(`${__dirname}/data/enc_message.transport`);

    it("should throw when key is not loaded into box", () => {
      const { error } = box.unwrap(p7s);
      assert.equal(error, "ENOKEY");
    });

    it("should throw if loaded key is marked as signature-only", () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv, cert });
      const { error } = boxWithKey.unwrap(p7s);
      assert.equal(error, "ENOKEY");
    });

    it("should use sender certificate from transport container", () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv: privEnc40A0, cert: toCert });
      const { content, error } = boxWithKey.unwrap(p7s);
      assert.equal(error, null);
      assert.deepEqual(content, Buffer.from("123"));
    });

    it("should unwrap if both certificates are present", () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv: privEnc40A0, cert: toCert });
      boxWithKey.load({ cert });
      const { content } = boxWithKey.unwrap(p7s);
      assert.deepEqual(content, Buffer.from("123"));
    });

    it("should supply all key material at initialisation time", () => {
      const keys = [
        { cert },
        { priv: privEnc40A0, cert: toCert },
        { priv: privEncE54B, cert: certE54B }
      ];
      const boxWithKey = new jk.Box({ algo, keys });
      boxWithKey.load({ priv: privEnc40A0, cert: toCert });
      boxWithKey.load({ cert });
      const { content } = boxWithKey.unwrap(p7s);
      assert.deepEqual(content, Buffer.from("123"));
    });

    it("should supply all key material at initialisation time and match keys with certificates itself", () => {
      const keys = [
        { cert },
        { cert: toCert },
        { cert: certE54B },
        { priv: privEnc40A0 },
        { priv: privEncE54B }
      ];
      const boxWithKey = new jk.Box({ algo, keys });
      boxWithKey.load({ priv: privEnc40A0, cert: toCert });
      boxWithKey.load({ cert });
      const { content } = boxWithKey.unwrap(p7s);
      assert.deepEqual(content, Buffer.from("123"));
    });
  });
});
