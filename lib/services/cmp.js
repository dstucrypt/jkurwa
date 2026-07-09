/*
 * CMP (Certificate Management Protocol) certificate lookup service.
 *
 * Fetches certificates from an IIT CMP server by their key identifiers.
 * The request/response bodies are DSTU CMS "data" ContentInfo messages whose
 * payload is a fixed-layout binary structure (not a standard ASN.1 request),
 * so the payload is assembled and parsed by raw byte offsets.
 */
import Message from "../models/Message.js";
import Certificate from "../models/Certificate.js";

// Build the raw CMP query payload wrapping one or two key identifiers.
// The 120-byte layout and magic constants below are dictated by the IIT
// server protocol and were reverse-engineered, hence the fixed offsets.
function makePayload(keyids) {
  /* black magic here. blame eeeeeet */
  var ct = Buffer.alloc(120);
  ct.fill(0);
  keyids[0].copy(ct, 0xc); // first key id at offset 12
  (keyids[1] || keyids[0]).copy(ct, 0x2c); // second key id at offset 44 (defaults to first)
  ct[0x6c] = 0x1;
  ct[0x70] = 0x1;
  ct[0x08] = 2;
  ct[0] = 0x0d;

  // Wrap the raw structure as a CMS "data" ContentInfo.
  var msg = new Message({ type: "data", data: ct });
  return msg.as_asn1();
}

// Parse a CMP server reply into an array of Certificate models, or null on
// any failure (malformed message, non-success status code, or missing data).
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
  // Status code lives at byte offset 4 (little-endian int32); 1 means success.
  var result = rmsg.info.readInt32LE(4);
  if (result !== 1) {
    return null;
  }
  // The actual certificate CMS message follows the 8-byte status header.
  rmsg = new Message(rmsg.info.slice(8));
  return rmsg.info.certificate.map(function (certData) {
    return new Certificate(certData);
  });
}

/**
 * Look up certificates on a CMP server by key identifier(s).
 * @param {Buffer[]} keyids One or two key identifier buffers to query for.
 * @param {string} url CMP server endpoint URL.
 * @param {function} query Transport callback (method, url, headers, body, cb).
 * @returns {Promise<Certificate[]>} Resolves with the found certificates;
 *   rejects with {reason: "http"|"data", ...} on transport or parse failure.
 */
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
        console.error("e", e);
      }
      if (!certificates) {
        return reject({ reason: "data" });
      }
      resolve(certificates);
    });
  });
}
export { lookup };
