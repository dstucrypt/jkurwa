/* eslint-env mocha */
import assert from "assert";
import { algos } from "gost89/lib/compat.js";

import * as jk from "../lib/index.js";
import * as pbes2 from "../lib/spec/pbes.js";
import * as pem from "../lib/util/pem.js";
import { loadAsset, loadPrivPem, assertEqualSaved } from "./utils.js";

const algo = algos();

describe("Keycoder", () => {
  const enc = loadAsset("STORE_A040.dat");
  const encPem = loadAsset("STORE_A040.pem").toString();
  const priv = loadPrivPem("Key40A0.pem");

  describe("#parse()", () => {
    it("should parse encrypted key in PEM format", () => {
      const [store] = jk.guess_parse(enc);
      assert.equal(store.format, "PBES2");
    });

    it("should serialize encrypted key to asn1", () => {
      const [store] = jk.guess_parse(enc);
      assert.deepEqual(pbes2.enc_serialize(store), enc);
    });

    it("should serialize encrypted key to PEM", () => {
      const [store] = jk.guess_parse(enc);
      assert.deepEqual(
        pem.to_pem(pbes2.enc_serialize(store), "ENCRYPTED PRIVATE KEY"),
        encPem
      );
    });

    it("should decrypt raw key from PBES2", () => {
      const {
        keys: [key]
      } = jk.Priv.from_protected(enc, "password", algo);
      assert.deepEqual(key, priv);
    });

    it("should decrypt raw key from PBES2 (PEM)", () => {
      const {
        keys: [key]
      } = jk.Priv.from_protected(encPem, "password", algo);
      assert.deepEqual(key, priv);
    });

    it("should encrypt raw key and serialize into PBES2", () => {
      const iv = Buffer.from("4bb10f5c2945d49e", "hex");
      const salt = Buffer.from(
        "31a58dc1462981189cf6c701e276c7553a5ab5f6e36d8418e4aa40c930cf3876",
        "hex"
      );
      const store = algo.storesave(
        Buffer.from(priv.to_asn1()),
        "PBES2",
        "password",
        iv,
        salt
      );

      assertEqualSaved(pbes2.enc_serialize(store), "STORE_A040.dat");
    });
  });
});
