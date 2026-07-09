/*
 * OCSP (Online Certificate Status Protocol, RFC 2560) client service.
 *
 * Builds a DER-encoded OCSPRequest for a single certificate (identified by a
 * CertID spec plus a nonce), POSTs it to the responder, and decodes the
 * OCSPResponse into an OcspResponse model. Uses the DSTU/GOST hash algorithm
 * for the CertID via ctx.hashFn.
 */
import fs from "fs";
import * as rfc2560 from "../spec/rfc2560-ocsp.js";
import Certificate from "../models/Certificate.js";
import OcspResponse from "../models/OcspResponse.js";

// Read a DER-encoded certificate from disk into a Certificate model.
function loadCert(path) {
  var buf = fs.readFileSync(path);
  return Certificate.from_asn1(buf);
}

// Encode and send an OCSPRequest, then decode the reply; invokes cb with an
// OcspResponse on a "successful" responseStatus, or null on any failure.
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
            // Nonce binds request to response to prevent replay attacks.
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
    function (full, status) {
      if (status !== 200) {
        return cb(null);
      }
      try {
        var rocsp = rfc2560.OCSPResponse.decode(full, "der");
      } catch (e) {
        return cb(null);
      }
      if (rocsp.responseStatus === "successful") {
        // responseBytes.response is the DER-encoded BasicOCSPResponse.
        cb(OcspResponse.fromBasic(rocsp.responseBytes.response));
      } else {
        cb(null);
      }
    }
  );
}

// Promise wrapper around requestCB: resolves the OcspResponse, rejects null.
function request(...args) {
  return new Promise((resolve, reject) => {
    requestCB(...args, ret => (ret ? resolve(ret) : reject(ret)));
  });
}

/**
 * Query the OCSP responder for the revocation status of a certificate.
 * @param {Certificate} cert Issuer certificate; also supplies the responder URL via cert.ocspLink.
 * @param {Buffer} serial Serial number of the certificate whose status is checked.
 * @param {Buffer} nonce Random nonce echoed back in the response.
 * @param {{hashFn: function, query: function}} ctx Hash function (DSTU/GOST) and transport callback.
 * @returns {Promise<OcspResponse>} Resolves with the decoded response; rejects on failure.
 */
async function lookup(cert, serial, nonce, ctx) {
  const spec = OcspResponse.encodeSpec(cert, serial, ctx.hashFn);
  return request(cert.ocspLink, spec, nonce, ctx.query);
}
export { lookup };
