/* eslint-env mocha */
const assert = require("assert");
const jk = require("../lib/index.js");

const keys = require("./data/keys");

describe("Keycoder", () => {
  const b257 = jk.std_curve("DSTU_PB_257");

  const b431 = jk.std_curve("DSTU_PB_431");

  function checkPB257(key) {
    assert.equal(key.type, "Priv");

    assert.equal(
      key.d.toString(true),
      "1111111111111111111111111111111111111111111111111111111111111111"
    );

    assert.equal(b257.equals(key.curve), true);
  }

  function checkPB431(key) {
    assert.equal(key.type, "Priv");
    assert.equal(
      key.d.toString(true),
      "888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
    );

    assert.equal(b431.equals(key.curve), true);
  }

  describe("#parse()", () => {
    it("should parse encrypted key in PEM format", () => {
      const store = jk.guess_parse(keys.PEM_KEY_ENC);
      assert.equal(store.format, "PBES2");
    });

    it("should parse raw key in PEM format", () => {
      let store = jk.guess_parse(keys.PEM_KEY_RAW);

      assert.equal(store.format, "privkeys");
      checkPB257(store.keys[0]);
      checkPB431(store.keys[1]);

      const key = jk.Priv.from_pem(keys.PEM_KEY_RAW);
      assert.equal(key.type, "Priv");
      checkPB257(key);

      store = jk.Priv.from_pem(keys.PEM_KEY_RAW, true);
      assert.equal(store.format, "privkeys");
      checkPB257(store.keys[0]);
      checkPB431(store.keys[1]);
    });
  });
});
