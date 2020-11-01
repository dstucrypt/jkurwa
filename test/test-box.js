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
  const cert6929 = jk.Certificate.from_asn1(
    fs.readFileSync(`${__dirname}/data/SELF_SIGNED_ENC_6929.cer`)
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
  const privEnc6929 = jk.Priv.from_asn1(
    fs.readFileSync(`${__dirname}/data/Key6929.cer`)
  );

  const box = new jk.Box({ algo });
  const time = 1540236305;

  const caList = new jk.models.Message();
  caList.wrap = {
    contentType: 'signedData',
    content: {
      version: 1,
      digestAlgorithms: [],
      contentInfo: { contentType: "data" },
      certificate: [cert, cert6929, toCert, certE54B].map(cert=> cert.ob),
      signerInfos: []
    }
  };

  describe("transport", () => {
    const transport = fs.readFileSync(`${__dirname}/data/message.transport`);

    it("should parse transport buffer headers", async () => {
      const {
        pipe: [head]
      } = await box.unwrap(transport);
      assert.deepEqual(head, {
        transport: true,
        headers: {
          EDRPOU: "1234567891",
          RCV_EMAIL: "user@tax.mail.com",
          DOC_TYPE: "3"
        }
      });
    });

    it("should parse message from transport buffer", async () => {
      const { content } = await box.unwrap(transport);
      assert.deepEqual(content, Buffer.from("123", "binary"));
    });
  });

  describe("signed p7s", () => {
    const p7s = fs.readFileSync(`${__dirname}/data/message.p7`);

    it("should return signed content", async () => {
      const { content } = await box.unwrap(p7s);
      assert.deepEqual(content, Buffer.from("123", "binary"));
    });

    it("should return certificate but warn its unverified", async () => {
      const { content, pipe } = await box.unwrap(p7s);
      assert.equal(pipe.length, 1);
      const [signed] = pipe;
      assert.equal(signed.signed, true);
      assert.deepEqual(signed.cert.subject, {
       "localityName": "Wakanda",
       "organizationName": "Very Much CA",
       "serialNumber": "UA-99999999",});
      assert.equal(!!signed.cert.verified, false);
    });

    it("should verify certificate against ca list", async () => {
      const boxWithCA = new jk.Box({ algo });
      boxWithCA.loadCAs(caList.as_asn1());
      const { content, pipe } = await boxWithCA.unwrap(p7s);
      assert.equal(pipe.length, 1);
      const [signed] = pipe;
      assert.equal(signed.signed, true);
      assert.deepEqual(signed.cert.subject, {
       "localityName": "Wakanda",
       "organizationName": "Very Much CA",
       "serialNumber": "UA-99999999",});
      assert.equal(signed.cert.verified, true);
    });

  });

  describe("detached sign p7s", () => {
    const p7s = fs.readFileSync(`${__dirname}/data/message_detached.p7`);

    it("should report error if message is no supplied", async () => {
      const { content, error } = await box.unwrap(p7s);
      assert.deepEqual(error, "ENODATA");
      assert.deepEqual(content, p7s);
    });

    it("should return signed content if supplied separately", async () => {
      const detachedContent = Buffer.from("123");
      const { content, error } = await box.unwrap(p7s, detachedContent);
      assert.equal(error, null);
      assert.deepEqual(content, detachedContent);
    });

    it("should return error if detached content does not match signature", async () => {
      const detachedContent = Buffer.from("1234");
      const { content, error } = await box.unwrap(p7s, detachedContent);
      assert.deepEqual(error, "ESIGN");
      assert.deepEqual(content, p7s);
    });
  });

  describe("encrypted p7s", () => {
    const p7s = fs.readFileSync(`${__dirname}/data/enc_message.p7`);

    it("should throw when key is not loaded into box", async () => {
      const { error } = await box.unwrap(p7s);
      assert.equal(error, "ENOKEY");
    });

    it("should throw if loaded key is marked as signature-only", async () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv, cert });
      const { error } = await boxWithKey.unwrap(p7s);
      assert.equal(error, "ENOKEY");
    });

    it("should return error if sender certificate is not found during lookup", async () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv: privEnc40A0, cert: toCert });
      const { error } = await boxWithKey.unwrap(p7s);
      assert.equal(error, "ENOCERT");
    });

    it("should return ENOKEY if receiver certiviate it not found during lookup", async () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv: privEncE54B, cert: certE54B });
      boxWithKey.load({ cert: cert6929 });
      const { error } = await boxWithKey.unwrap(p7s);
      assert.equal(error, "ENOKEY");
    });

    it("should return ENOKEY if encryption certificate found, but has no matching key", async () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv: privEncE54B, cert: toCert });
      boxWithKey.load({ cert: cert6929 });
      const { error } = await boxWithKey.unwrap(p7s);
      assert.equal(error, "ENOKEY");
    });

    it("should throw mismatch error if KEK checksum fails for found key", async () => {
      /* This test deliberately confuses library by creating serial number
       * collision and supplying matching certificate with wrong key
       * This error is not a part of normal operation. */
      const boxWithKey = new jk.Box({ algo });
      const wicked6929 = jk.Certificate.from_asn1(cert6929.to_asn1());
      wicked6929.pubkey.point.y.bytes[1] |= 0xff;
      boxWithKey.load({ priv: privEnc40A0, cert: toCert });
      boxWithKey.load({ cert: wicked6929 });

      assert.rejects(
        () => boxWithKey.unwrap(p7s),
        /Key unwrap failed. Checksum mismatch/
      );
    });

    it("should unwrap be okay if right certificate is before wrong one (collision)", async () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv: privEnc40A0, cert: toCert });
      boxWithKey.load({ priv: privEncE54B, cert: certE54B });
      boxWithKey.load({ cert: cert6929 });
      const { content, error } = await boxWithKey.unwrap(p7s);
      assert.equal(error, null);
      assert.deepEqual(content, Buffer.from("123"));
    });

    it("should unwrap if both certificates are present", async () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv: privEnc40A0, cert: toCert });
      boxWithKey.load({ cert: cert6929 });
      const { content, error } = await boxWithKey.unwrap(p7s);
      assert.equal(error, null);
      assert.deepEqual(content, Buffer.from("123"));
    });
  });

  describe("encrypted transport", () => {
    const p7s = fs.readFileSync(`${__dirname}/data/enc_message.transport`);

    it("should report ENOKEY if key is not loaded into box", async () => {
      const { error } = await box.unwrap(p7s);
      assert.equal(error, "ENOKEY");
    });

    it("should report ENOKEY if loaded key is marked as signature-only", async () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv, cert });
      const { error } = await boxWithKey.unwrap(p7s);
      assert.equal(error, "ENOKEY");
    });

    it("should use sender certificate from transport container", async () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({ priv: privEnc40A0, cert: toCert });
      const { content, error } = await boxWithKey.unwrap(p7s);
      assert.equal(error, null);
      assert.deepEqual(content, Buffer.from("123"));
    });

    it("should supply all key material at initialisation time", async () => {
      const keys = [
        { cert: cert6929 },
        { priv: privEnc40A0, cert: toCert },
        { priv: privEncE54B, cert: certE54B }
      ];
      const boxWithKey = new jk.Box({ algo, keys });
      const { content, error } = await boxWithKey.unwrap(p7s);
      assert.equal(error, null);
      assert.deepEqual(content, Buffer.from("123"));
    });

    it("should supply all key material at initialisation time and match keys with certificates itself", async () => {
      const keys = [
        { cert: cert6929 },
        { cert: toCert },
        { cert: certE54B },
        { priv: privEnc40A0 },
        { priv: privEncE54B }
      ];
      const boxWithKey = new jk.Box({ algo, keys });
      const { content } = await boxWithKey.unwrap(p7s);
      assert.deepEqual(content, Buffer.from("123"));
    });

    describe("deprecated", () => {
      beforeAll(() => {
        jk.Box.EOLD.silent = true;
      });
      afterAll(() => {
        jk.Box.EOLD.silent = false;
      });

      it("should read key material from filesystem", async () => {
        const boxWithKey = new jk.Box({ algo });
        boxWithKey.load({ privPath: `${__dirname}/data/Key40A0.cer` });
        boxWithKey.load({
          certPath: `${__dirname}/data/SELF_SIGNED_ENC_40A0.cer`
        });
        const { content } = await boxWithKey.unwrap(p7s);
        assert.deepEqual(content, Buffer.from("123"));
      });

      it("should read key material from DER/PEM", async () => {
        const boxWithKey = new jk.Box({ algo });
        boxWithKey.load({
          privPath: `${__dirname}/data/STORE_A040.pem`,
          password: "password"
        });
        boxWithKey.load({
          certPath: `${__dirname}/data/SELF_SIGNED_ENC_40A0.cer`
        });
        const { content } = await boxWithKey.unwrap(p7s);
        assert.deepEqual(content, Buffer.from("123"));
      });
    });

    it("should read encrypted key from filesystem", async () => {
      const boxWithKey = new jk.Box({ algo });
      boxWithKey.load({
        privPem: fs.readFileSync(`${__dirname}/data/Key40A0.pem`)
      });
      boxWithKey.load({
        certPem: fs.readFileSync(`${__dirname}/data/SELF_SIGNED_ENC_40A0.cer`)
      });
      const { content } = await boxWithKey.unwrap(p7s);
      assert.deepEqual(content, Buffer.from("123"));
    });
  });

  describe("clear data container", () => {
    it("should expect to see asn1 structure in transport container", async () => {
      const clear = fs.readFileSync(
        `${__dirname}/data/clear_message.transport`
      );
      assert.rejects(() => box.unwrap(clear), /Failed to match tag/);
    });

    it("should pass cleartext back if it does not match any format", async () => {
      const { content } = await box.unwrap(Buffer.from("123"));
      assert.deepEqual(content, Buffer.from("123"));
    });
  });

  describe("create signature", () => {
    const boxWithKey = new jk.Box({ algo });
    boxWithKey.load({ priv, cert });

    it("should sign message with signing key", done => {
      boxWithKey
        .pipe(
          Buffer.from("123"),
          [{ op: "sign", time }],
          {}
        )
        .then(data =>
          assert.deepEqual(
            data,
            fs.readFileSync(`${__dirname}/data/message.p7`)
          )
        )
        .then(done);
    });

    it("should sign message with signing key (async)", done => {
      boxWithKey
        .pipe(
          Buffer.from("123"),
          [{ op: "sign", time }]
        )
        .then(data => {
          assert.deepEqual(
            data,
            fs.readFileSync(`${__dirname}/data/message.p7`)
          );
        })
        .then(done);
    });
  });

  describe("encrypt message", () => {
    const boxWithKey = new jk.Box({ algo });
    boxWithKey.load({ priv: privEnc6929, cert: cert6929 });

    it("should throw if receipient not specified", async () => {
      assert.rejects(
        () =>
          boxWithKey.pipe(
            Buffer.from("123"),
            [{ op: "encrypt" }],
            {}
          ),
        /No recipient specified for encryption/
      );
    });

    it("should encrypt message with encryption key", done => {
      boxWithKey
        .pipe(
          Buffer.from("123"),
          [{ op: "encrypt", forCert: toCert }]
        )
        .then(data =>
          assert.deepEqual(
            data,
            fs.readFileSync(`${__dirname}/data/enc_message.p7`)
          )
        )
        .then(done);
    });

    it("should encrypt message with encryption key and recipient passed as PEM", done => {
      boxWithKey
        .pipe(
          Buffer.from("123"),
          [{ op: "encrypt", forCert: toCert.to_pem() }],
          {}
        )
        .then(data =>
          assert.deepEqual(
            data,
            fs.readFileSync(`${__dirname}/data/enc_message.p7`)
          )
        )
        .then(done);
    });

    it("should encrypt message with encryption key (async)", done => {
      boxWithKey
        .pipe(
          Buffer.from("123"),
          [{ op: "encrypt", forCert: toCert }]
        )
        .then(data =>
          assert.deepEqual(
            data,
            fs.readFileSync(`${__dirname}/data/enc_message.p7`)
          )
        )
        .then(done);
    });
  });
});
