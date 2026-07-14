/* eslint-env jest */
const gost89 = require("gost89");
const fs = require("fs");
const path = require("path");
const jk = require("../lib");

const dataDir = path.join(__dirname, "data");

function loadAsset(filename) {
  return fs.readFileSync(path.join(dataDir, filename));
}

describe("CZO CAdES-X Long GOST", () => {
  const gostHash = gost89.compat.algos().hash;
  const p7s = loadAsset("test-x-gost.p7s");

  function makeBox() {
    return new jk.Box({
      algo: { hash: gostHash, hashes: { Gost34311: gostHash, Dstu4145le: gostHash } }
    });
  }

  it("unwraps with CA verification", async () => {
    const box = makeBox();
    box.loadCAs(loadAsset("CZO-CA-LIST.p7s"));
    const { content, pipe } = await box.unwrap(p7s);
    expect(content.toString()).toBe("Test\r\n");
    expect(pipe[0].signed).toBe(true);
    expect(pipe[0].cert.verified).toBe(true);
  });
});
