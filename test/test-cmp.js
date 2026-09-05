import { describe, it } from "vitest";
import assert from "assert";
import * as jk from "../lib/index.js";
import * as cmpService from "../lib/services/cmp.js";
import { loadAsset } from "./utils.js";

const { ContentInfo } = jk.dstszi2010;

// Builds the outer CMS `data` ContentInfo envelope that the CMP service
// wraps every reply in. `content` is the raw octet-string payload: 8 bytes
// (opcode + status) on failure, or that header followed by a nested
// message on success.
function buildResponse(content) {
  return ContentInfo.encode({ contentType: "data", content }, "der");
}

function buildStatusResponse(status) {
  const header = Buffer.alloc(8);
  header.writeInt32LE(0x0d, 0); // echoes the request opcode
  header.writeInt32LE(status, 4);
  return buildResponse(header);
}

function buildSuccessResponse(certs) {
  const header = Buffer.alloc(8);
  header.writeInt32LE(0x0d, 0);
  header.writeInt32LE(1, 4); // 1 == success

  // The nested message is itself a CMS SignedData whose only field cmp.js
  // reads is `certificate`; version/digestAlgorithms/signerInfos are left
  // empty since unpack() never looks at them.
  const nested = ContentInfo.encode(
    {
      contentType: "signedData",
      content: {
        version: 1,
        digestAlgorithms: [],
        contentInfo: { contentType: "data" },
        certificate: certs.map(cert => cert.ob),
        signerInfos: []
      }
    },
    "der"
  );

  return buildResponse(Buffer.concat([header, nested]));
}

// A `query` stub matching the (method, url, headers, payload, cb) signature
// `lookup()` calls, so tests never touch the network.
function stubQuery(response, status = 200) {
  return (method, url, headers, payload, cb) => cb(response, status);
}

describe("cmp service", () => {
  const cert = jk.Certificate.from_asn1(loadAsset("SELF_SIGNED1.cer"));
  const keyids = [Buffer.alloc(32, 1)];

  it("unpacks a successful response into certificates", async () => {
    // Regression test for the undeclared `certificates` assignment in
    // unpack(): under strict mode (as in the built ESM output) that line
    // throws `ReferenceError: certificates is not defined` on exactly this
    // - the success - path, so this case used to be the one guaranteed to
    // fail.
    const response = buildSuccessResponse([cert]);

    const certificates = await cmpService.lookup(
      keyids,
      "http://cmp.example.test/",
      stubQuery(response)
    );

    assert.equal(certificates.length, 1);
    assert.ok(certificates[0] instanceof jk.Certificate);
    assert.equal(certificates[0].rdnSerial(), cert.rdnSerial());
  });

  it("rejects a status-9 response as a distinguishable not-found, not a parse error", async () => {
    const response = buildStatusResponse(9);

    await assert.rejects(
      () => cmpService.lookup(keyids, "http://cmp.example.test/", stubQuery(response)),
      err => {
        assert.equal(err.status, 9);
        assert.equal(err.reason, "not-found");
        assert.notEqual(err.reason, "data");
        return true;
      }
    );
  });

  it("still rejects with reason 'data' (and the causing error attached) when the response cannot be parsed at all", async () => {
    const garbage = Buffer.from([0xff, 0x00, 0x01, 0x02]);

    await assert.rejects(
      () => cmpService.lookup(keyids, "http://cmp.example.test/", stubQuery(garbage)),
      err => {
        assert.equal(err.reason, "data");
        return true;
      }
    );
  });

  it("rejects with reason 'http' on a non-200 response, unchanged", async () => {
    await assert.rejects(
      () =>
        cmpService.lookup(
          keyids,
          "http://cmp.example.test/",
          stubQuery(Buffer.alloc(0), 404)
        ),
      err => {
        assert.equal(err.reason, "http");
        assert.equal(err.status, 404);
        return true;
      }
    );
  });
});
