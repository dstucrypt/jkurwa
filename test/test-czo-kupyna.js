/* eslint-env jest */
const gost89 = require("gost89");
const dstu7564 = require("dstu7564");
const fs = require("fs");
const path = require("path");
const jk = require("../lib");

const dataDir = path.join(__dirname, "data");

function loadAsset(filename) {
  return fs.readFileSync(path.join(dataDir, filename));
}

describe("CZO CAdES-BES Dstu7564 (Kupyna)", () => {
  const gostHash = gost89.compat.algos().hash;
  const kupynaHash = function (d) {
    return dstu7564.computeHash(32, d);
  };
  const p7s = loadAsset("test-kupyna-czo.p7s");

  function makeBox() {
    return new jk.Box({
      algo: {
        hash: kupynaHash,
        hashes: {
          Gost34311: gostHash,
          Dstu4145le: gostHash,
          "Dstu4145leWithDstu7564": kupynaHash,
          Dstu7564: kupynaHash,
          "Dstu7564-256": kupynaHash,
        },
      },
    });
  }

  it("unwraps and verifies Kupyna signature", async () => {
    const box = makeBox();
    const { content, pipe } = await box.unwrap(p7s);
    expect(content.toString()).toBe("Test\r\n");
    expect(pipe[0].signed).toBe(true);
    expect(pipe[0].cert.subject.commonName).toBe(
      "ТЕСТ Тестовий Тест Тестович"
    );
  });

  it("unwraps with CA verification using test root", async () => {
    const box = makeBox();
    box.loadCAs(loadAsset("CZO-CA-LIST.p7s"));
    const { content, pipe } = await box.unwrap(p7s);
    expect(content.toString()).toBe("Test\r\n");
    expect(pipe[0].signed).toBe(true);
    expect(pipe[0].cert.verified).toBe(true);
  });
});
