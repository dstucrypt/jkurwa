var fs = require("fs");
var rfc2560 = require("../spec/rfc2560-ocsp");
var Certificate = require("../models/Certificate");
var OcspResponse = require("../models/OcspResponse");

function loadCert(path) {
  var buf = fs.readFileSync(path);
  return Certificate.from_asn1(buf);
}

function requestCB(url, spec, nonce, query, cb) {
  var ocsp = rfc2560.OCSPRequest.encode(
    {
      tbsRequest: {
        requestList: [
          {
            reqCert: spec
          }
        ],
        requestExtensions: [
          {
            extnID: "OCSPNonce",
            extnValue: nonce
          }
        ]
      }
    },
    "der"
  );
  return query(
    "POST",
    url,
    {
      "Content-Type": "application/ocsp-request",
      "Content-Length": ocsp.length
    },
    ocsp,
    function(full, status) {
      if (status !== 200) {
        return cb(null);
      }
      try {
        var rocsp = rfc2560.OCSPResponse.decode(full, "der");
      } catch (e) {
        return cb(null);
      }
      if (rocsp.responseStatus === "successful") {
        cb(OcspResponse.fromBasic(rocsp.responseBytes.response));
      } else {
        cb(null);
      }
    }
  );
}

function request(...args) {
  return new Promise((resolve, reject) => {
    requestCB(...args, ret => (ret ? resolve(ret) : reject(ret)));
  });
}

async function lookup(cert, serial, nonce, ctx) {
  const spec = OcspResponse.encodeSpec(cert, serial, ctx.hashFn);
  return request(cert.ocspLink, spec, nonce, ctx.query);
}
module.exports = { lookup };
