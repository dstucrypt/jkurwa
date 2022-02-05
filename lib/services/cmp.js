var Message = require("../models/Message");
var Certificate = require("../models/Certificate");

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
    return null;
  }
  rmsg = new Message(rmsg.info.slice(8));
  return (certificates = rmsg.info.certificate.map(function (certData) {
    return new Certificate(certData);
  }));
}

function lookup(keyids, url, query) {
  const payload = makePayload(keyids);
  const headers = {
    "Content-Length": payload.length,
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
module.exports = { lookup };
