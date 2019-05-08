/* eslint-env mocha */
const fs = require('fs');
const assert = require("assert");
const algo = require('gost89/lib/compat').algos();

const jk = require("../lib/index.js");
const pbes2 = require('../lib/spec/pbes.js');
const pem = require('../lib/util/pem.js');


describe("Keycoder", () => {
  const enc = fs.readFileSync(`${__dirname}/data/STORE_A040.dat`);
  const encPem = fs.readFileSync(`${__dirname}/data/STORE_A040.pem`).toString();
  const priv = jk.Priv.from_pem(
    fs.readFileSync(`${__dirname}/data/Key40A0.pem`)
  );

  describe("#parse()", () => {
    it("should parse encrypted key in PEM format", () => {
      const store = jk.guess_parse(enc);
      assert.equal(store.format, "PBES2");
    });

    it("should serialize encrypted key to asn1", () => {
      const store = jk.guess_parse(enc);
      assert.deepEqual(pbes2.enc_serialize(store), enc);
    });

    it("should serialize encrypted key to PEM", () => {
      const store = jk.guess_parse(enc);
      assert.deepEqual(
        pem.to_pem(pbes2.enc_serialize(store), 'ENCRYPTED PRIVATE KEY'),
        encPem,
      );
    });

    it("should decrypt raw key from PBES2", () => {
      const {keys: [key]} = jk.Priv.from_protected(enc, "password", algo);
      assert.deepEqual(key, priv);
    });

   it("should decrypt raw key from PBES2 (PEM)", () => {
      const {keys: [key]} = jk.Priv.from_protected(encPem, "password", algo);
      assert.deepEqual(key, priv);
    });

    it("should encrypt raw key and serialize into PBES2", () => {
      const iv = Buffer.from('4bb10f5c2945d49e', 'hex');
      const salt = Buffer.from('31a58dc1462981189cf6c701e276c7553a5ab5f6e36d8418e4aa40c930cf3876', 'hex');
      const store = algo.storesave(
        Buffer.from(priv.to_asn1()), 'PBES2', 'password', iv, salt,
      );

      assert.deepEqual(
        fs.readFileSync(`${__dirname}/data/STORE_A040.dat`),
        pbes2.enc_serialize(store)
      );
    });
  });
});
