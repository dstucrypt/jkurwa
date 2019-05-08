/* eslint-env mocha */
const gost89 = require("gost89");
const assert = require("assert");
const fs = require("fs");

const jk = require("../lib");
const Message = require("../lib/models/Message");

const NOT_RANDOM_32 = Buffer.from("12345678901234567890123456789012");

global.crypto = {
  // Moch random only for testing purposes.
  // SHOULD NOT BE USED IN REAL CODE.
  getRandomValues() {
    return NOT_RANDOM_32;
  }
};

function assertEqualSaved(buffer, filename) {
  assert.deepEqual(fs.readFileSync(filename), buffer);
}

describe("Signed Message", () => {
  const key1 = jk.Priv.from_asn1(
    fs.readFileSync(`${__dirname}/data/PRIV1.cer`),
  );
  const privEnc6929 = jk.Priv.from_asn1(
    fs.readFileSync(`${__dirname}/data/Key6929.cer`),
  );

  const data = Buffer.from("123");
  const algo = gost89.compat.algos();
  const dataHash = algo.hash(data);
  const sign = Buffer.from(
    "a2f0f6927e40a651876548c53052dba0f6240adb5d0bffa23b5ed617c4398a600dd1257022b776eb16290c71de9804600307ecb01a2990c387ab7269dd44d917",
    "hex"
  );
  const time = 1540236305;
  const lateTime = 1740236305;

  const cert = jk.Certificate.from_asn1(
    fs.readFileSync(`${__dirname}/data/SELF_SIGNED1.cer`)
  );
  const encCert = jk.Certificate.from_asn1(
    fs.readFileSync(`${__dirname}/data/SELF_SIGNED_ENC_6929.cer`)
  );
  const toCert = jk.Certificate.from_asn1(
    fs.readFileSync(`${__dirname}/data/SELF_SIGNED_ENC_40A0.cer`)
  );
  const otherCert = jk.Certificate.from_asn1(
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
    assertEqualSaved(message.as_asn1(), `${__dirname}/data/message.p7`);
  });

  it("should serialize detached sign to asn1 buffer", () => {
    const message = new Message({
      type: "signedData",
      cert,
      dataHash,
      hash: algo.hash,
      signTime: time,
      signer: key1
    });

    assertEqualSaved(message.as_asn1(), `${__dirname}/data/message_detached.p7`);
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
    assertEqualSaved(transport, `${__dirname}/data/message.transport`)
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
    assert.equal(
      transport.slice(0, 9).toString("binary"),
      "UA1_SIGN\0"
    );
    assertEqualSaved(
      transport.slice(13),
      `${__dirname}/data/message.p7`
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
      signer: key1,
      signTime: lateTime,
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

  it("should pass verification", () => {
    const message = new Message(
      fs.readFileSync(`${__dirname}/data/message.p7`)
    );
    assert.equal(message.verify(algo.hash), true);
  });

  it("should fail verification if cert does not match", () => {
    const message = new Message({
      type: "signedData",
      cert: otherCert,
      data,
      hash: algo.hash,
      signTime: time,
      signer: key1
    });
    assert.equal(message.verify(algo.hash), false);
  });

  it("should encrypt and serialize message", () => {
    const message = new Message({
      type: "envelopedData",
      data,
      cert: encCert,
      toCert,
      crypter: privEnc6929,
      algo
    });
    assertEqualSaved(
      message.as_asn1(),
      `${__dirname}/data/enc_message.p7`
    );
  });

  it("should serialize encrypted message to transport format", () => {
    const message = new Message({
      type: "envelopedData",
      data,
      cert: encCert,
      toCert,
      crypter: privEnc6929,
      algo
    });
    const transport = message.as_transport();
    assert.deepEqual(
      transport.slice(0, 10).toString("binary"),
      "UA1_CRYPT\0"
    );
    assertEqualSaved(
      transport.slice(0xe),
      `${__dirname}/data/enc_message.p7`
    );
  });

  it("should serialize encrypted message to transport format including cert", () => {
    const message = new Message({
      type: "envelopedData",
      data,
      cert: encCert,
      toCert,
      crypter: privEnc6929,
      algo
    });
    const transport = message.as_transport({}, cert);
    assert.deepEqual(
      transport.slice(0, 0x13).toString("binary"),
      "TRANSPORTABLE\0\x01\0\0\0\0"
    );
    assert.deepEqual(
      transport.slice(0x13, 0x13 + 10).toString("binary"),
      "CERTCRYPT\0"
    );

    assert.equal(cert.to_asn1().length, 0x20d);
    assert.deepEqual(
      transport.slice(0x13 + 0xe, 0x13 + 0xe + 0x20d),
      encCert.to_asn1()
    );
    assert.deepEqual(
      transport
        .slice(0x13 + 0xe + 0x20D, 0x13 + 0xe + 0x20D + 10)
        .toString("binary"),
      "UA1_CRYPT\0"
    );
    assertEqualSaved(
      transport,
      `${__dirname}/data/enc_message.transport`
    );
  });
});
