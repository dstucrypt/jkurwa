import { describe, it } from "vitest";
import assert from "assert";
import * as jk from "../lib/index.js";
import * as cmp from "../lib/services/cmp.js";
import { loadAsset } from "./utils.js";

const { ContentInfo } = jk.dstszi2010;

function successResponse(certs) {
  const header = Buffer.alloc(8);
  header.writeInt32LE(0x0d, 0);
  header.writeInt32LE(1, 4);
  const signed = ContentInfo.encode(
    {
      contentType: "signedData",
      content: {
        version: 1,
        digestAlgorithms: [],
        contentInfo: { contentType: "data" },
        certificate: certs.map((c) => c.ob),
        signerInfos: []
      }
    },
    "der"
  );
  return ContentInfo.encode(
    { contentType: "data", content: Buffer.concat([header, signed]) },
    "der"
  );
}

describe("cmp service", () => {
  it("lookup resolves certificates from a success response", async () => {
    const cert = jk.Certificate.from_asn1(loadAsset("SELF_SIGNED1.cer"));
    const response = successResponse([cert]);
    const certificates = await cmp.lookup(
      [Buffer.alloc(32, 1)],
      "http://cmp.example.test/",
      (method, url, headers, payload, cb) => cb(response, 200)
    );
    assert.equal(certificates.length, 1);
    assert.ok(certificates[0] instanceof jk.Certificate);
  });
});
