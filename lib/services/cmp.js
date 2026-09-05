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
  var result = rmsg.info.readInt32LE(4);
  if (result !== 1) {
    // A well-formed response that isn't a success (e.g. status 9 - "no
    // certificate for this key identifier") is not a parse failure: throw
    // a tagged error so lookup() can tell it apart from a response that
    // could not be parsed at all.
    var statusError = new Error("cmp: server returned status " + result);
    statusError.cmpStatus = result;
    throw statusError;
  }
  rmsg = new Message(rmsg.info.slice(8));
  var certificates = rmsg.info.certificate.map(function(certData) {
    return new Certificate(certData);
  });
  return certificates;
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
      let certificates;
      try {
        certificates = unpack(response);
      } catch (e) {
        // Surface the real error instead of swallowing it: a status-9
        // ("no certificate for this key identifier") response is a clean,
        // distinguishable not-found rather than a parse failure. Anything
        // else (including bugs in unpack() itself) keeps the pre-existing
        // "data" reason, but now carries the original error too.
        const reason = e && e.cmpStatus === 9 ? "not-found" : "data";
        return reject({ reason, status: e && e.cmpStatus, error: e });
      }
      if (!certificates) {
        return reject({ reason: "data" });
      }
      resolve(certificates);
    });
  });
}
export { lookup };
