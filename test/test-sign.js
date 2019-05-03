/* eslint-env mocha */
const gost89 = require("gost89");
const assert = require("assert");
const fs = require("fs");

const jk = require("../lib");
const Message = require("../lib/models/Message");

const keys = require("./data/keys");

const NOT_RANDOM_32 = Buffer.from("12345678901234567890123456789012");

global.crypto = {
  // Moch random only for testing purposes.
  // SHOULD NOT BE USED IN REAL CODE.
  getRandomValues() {
    return NOT_RANDOM_32;
  }
};

describe("Signed Message", () => {
  const store = jk.guess_parse(keys.PEM_KEY_RAW);
  const [key1] = store.keys;
  const data = Buffer.from("123");
  const algo = gost89.compat.algos();
  const dataHash = algo.hash(data);
  const sign = Buffer.from(
    "e45fe541d047ae546825f91db53906306024ad12fcbe8185b9fce2e615e52b2084dad217d37612ee8761da493db0c4570ac5d323c649b1c83093897536b23a5b",
    "hex"
  );
  const time = 1540236305;

  const cert = jk.Certificate.from_asn1(
    fs.readFileSync(`${__dirname}/data/SFS_1.cer`)
  );

  it("should sign data using privkey", () => {
    const message = new Message({
      type: "signedData",
      cert,
      data,
      hash: algo.hash,
      signTime: time,
      signer: key1
    });
    assert.equal(message.wrap.content.contentInfo.content, data);
    const [signInfo] = message.wrap.content.signerInfos;
    assert.deepEqual(signInfo.encryptedDigest, sign);
    assert.equal(time * 1000, message.pattrs.signingTime);
  });

  it("should sign hash using privkey", () => {
    const message = new Message({
      type: "signedData",
      cert,
      dataHash,
      hash: algo.hash,
      signTime: time,
      signer: key1
    });
    assert.equal(message.wrap.content.contentInfo.content, undefined);
    const [signInfo] = message.wrap.content.signerInfos;
    assert.deepEqual(signInfo.encryptedDigest, sign);
  });

  it("should serialize to asn1 buffer", () => {
    const message = new Message({
      type: "signedData",
      cert,
      data,
      hash: algo.hash,
      signTime: time,
      signer: key1
    });

    assert.deepEqual(
      message.as_asn1(),
      fs.readFileSync(`${__dirname}/data/message.p7`)
    );
  });

  it("should serialize to transport format (tax office)", () => {
    const message = new Message({
      type: "signedData",
      cert,
      data,
      hash: algo.hash,
      signTime: time,
      signer: key1
    });

    const transport = message.as_transport({
        EDRPOU: '1234567891',
        RCV_EMAIL: 'user@tax.mail.com',
        DOC_TYPE: '3',
    });
    assert.equal(
      transport.slice(0, 14).toString("binary"),
      "TRANSPORTABLE\0"
    );
    assert.deepEqual(
      transport,
      fs.readFileSync(`${__dirname}/data/message.transport`)
    );
  });

  it("should serialize to transport format with headers (tax office)", () => {
    const message = new Message({
      type: "signedData",
      cert,
      data,
      hash: algo.hash,
      signTime: time,
      signer: key1
    });

    const transport = message.as_transport();
    assert.equal(transport.length, 0x0b1f + 0xd);
    assert.equal(
      transport.slice(0, 13).toString("binary"),
      "UA1_SIGN\0\x1F\x0B\x00\x00"
    );
    assert.deepEqual(
      transport.slice(13),
      fs.readFileSync(`${__dirname}/data/message.p7`)
    );
  });

  it("should parse message from asn1 buffer", () => {
    const message = new Message(
      fs.readFileSync(`${__dirname}/data/message.p7`)
    );
    const [signInfo] = message.wrap.content.signerInfos;
    assert.deepEqual(signInfo.encryptedDigest, sign);
    assert.deepEqual(message.wrap.content.contentInfo.content, data);
    const [signCert] = message.wrap.content.certificate;
    assert.deepEqual(new jk.Certificate(signCert).as_dict(), cert.as_dict());
    assert.equal(time * 1000, message.pattrs.signingTime);
  });

  it("should check digest and signing time against certificate validity range", () => {
    const message = new Message(
      fs.readFileSync(`${__dirname}/data/message.p7`)
    );
    assert.equal(message.verifyAttrs(algo.hash), true);
  });

  it("should fail attribute check if time is not specified (expired cert)", () => {
    const message = new Message({
      type: "signedData",
      cert,
      data,
      hash: algo.hash,
      signer: key1
    });
    assert.equal(message.verifyAttrs(algo.hash), false);
  });

  it("should fail attribute check if data does not match digest", () => {
    const message = new Message({
      type: "signedData",
      cert,
      data,
      dataHash: Buffer.from("12345678901234567890123456789098"),
      hash: algo.hash,
      signTime: time,
      signer: key1
    });
    assert.equal(message.verifyAttrs(algo.hash), false);
  });

  it("should fail verification (pubkey does not match certificate)", () => {
    const message = new Message(
      fs.readFileSync(`${__dirname}/data/message.p7`)
    );
    assert.equal(message.verify(algo.hash), false);
  });

  it("should encrypt and serialize message", () => {
    const message = new Message({
      type: "envelopedData",
      data,
      cert, // this certificate does not match private key
      toCert: cert,
      crypter: key1,
      algo
    });
    assert.deepEqual(
      message.as_asn1(),
      fs.readFileSync(`${__dirname}/data/enc_message.p7`)
    );
  });

  it("should serialize encrypted message to transport format", () => {
    const message = new Message({
      type: "envelopedData",
      data,
      cert,
      toCert: cert,
      crypter: key1,
      algo
    });
    const transport = message.as_transport();
    assert.equal(transport.length, 0x0406 + 0xe);
    assert.deepEqual(
      transport.slice(0, 0xe).toString("binary"),
      "UA1_CRYPT\0\x06\x04\0\0"
    );
    assert.deepEqual(
      transport.slice(0xe),
      fs.readFileSync(`${__dirname}/data/enc_message.p7`)
    );
  });

  it("should serialize encrypted message to transport format including cert", () => {
    const message = new Message({
      type: "envelopedData",
      data,
      cert,
      toCert: cert,
      crypter: key1,
      algo
    });
    const transport = message.as_transport({}, cert);
    assert.equal(transport.length, 0x0406 + 0xe + 0x6f2);
    assert.deepEqual(
      transport.slice(0, 0x13).toString("binary"),
      "TRANSPORTABLE\0\x01\0\0\0\0"
    );
    assert.deepEqual(
      transport.slice(0x13, 0x13 + 0xe).toString("binary"),
      "CERTCRYPT\0\xD1\x06\0\0"
    );

    assert.equal(cert.to_asn1().length, 0x6d1);
    assert.deepEqual(
      transport.slice(0x13 + 0xe, 0x13 + 0xe + 0x6d1),
      cert.to_asn1()
    );
    assert.deepEqual(
      transport
        .slice(0x13 + 0xe + 0x6d1, 0x13 + 0xe + 0x6d1 + 0xe)
        .toString("binary"),
      "UA1_CRYPT\0\x06\x04\0\0"
    );
    assert.deepEqual(
      transport.slice(0x13 + 0xe + 0x6d1 + 0xe),
      fs.readFileSync(`${__dirname}/data/enc_message.p7`)
    );
  });
});
