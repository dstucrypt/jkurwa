import Message from "../models/Message.js";
import Certificate from "../models/Certificate.js";

function makePayload(keyids) {
  /* black magic here. blame eeeeeet */
  var ct = Buffer.alloc(120);
  ct.fill(0);
  keyids[0].copy(ct, 0xc);
  (keyids[1] || keyids[0]).copy(ct, 0x2c);
  ct[0x6c] = 0x1;
  ct[0x70] = 0x1;
  ct[0x08] = 2;
  ct[0] = 0x0d;

  var msg = new Message({ type: "data", data: ct });
  return msg.as_asn1();
}

function unpack(resp) {
  var rmsg;
  try {
    rmsg = new Message(resp);
  } catch (e) {
    return null;
  }

  if (!rmsg.info) {
    return null;
  }
  const status = rmsg.info.readInt32LE(4);
  if (status !== 1) {
    // A well-formed response that isn't a success (e.g. status 9 - "no
    // certificate for this key identifier") is not a parse failure, so it
    // reports the status instead. `null` stays reserved for "could not be
    // parsed at all", which is what lets lookup() tell the two apart.
    return { status: status, certificates: null };
  }
  rmsg = new Message(rmsg.info.slice(8));
  const certificates = rmsg.info.certificate.map(function(certData) {
    return new Certificate(certData);
  });
  return { status: status, certificates: certificates };
}

function lookup(keyids, url, query) {
  const payload = makePayload(keyids);
  const headers = {
    "Content-Length": payload.length
  };
  return new Promise((resolve, reject) => {
    query("POST", url, headers, payload, (response, status) => {
      if (status !== 200) {
        return reject({ reason: "http", status });
      }
      let parsed;
      try {
        parsed = unpack(response);
      } catch (e) {
        // Not a protocol outcome - unpack() reports those by return value.
        // Reaching here means unpack() itself threw, so surface the error
        // rather than swallowing it behind a bare "data" as before.
        return reject({ reason: "data", error: e });
      }
      if (!parsed) {
        return reject({ reason: "data" });
      }
      if (!parsed.certificates) {
        // Status 9 is "no certificate for this key identifier" - a clean
        // not-found. Every other non-success status keeps the pre-existing
        // "data" reason, so callers checking for it are unaffected and
        // simply gain `status`.
        const reason = parsed.status === 9 ? "not-found" : "data";
        return reject({ reason, status: parsed.status });
      }
      resolve(parsed.certificates);
    });
  });
}
export { lookup };
