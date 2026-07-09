/*
 * TSP (Time-Stamp Protocol, RFC 3161) client service.
 *
 * Requests a time-stamp token for a message digest from a TSA (Time-Stamping
 * Authority). The digest is expected to be produced with the DSTU/GOST 34311
 * hash by default. The returned token is re-encoded as a DSTU CMS ContentInfo
 * so it can be embedded into a signature as an unsigned attribute.
 */
import rfc3161 from "../spec/rfc3161-tsp.js";
import Certificate from "../models/Certificate.js";
import gost89 from "gost89";
import * as dstszi2010 from "../spec/dstszi2010.js";

// Encode and POST a TimeStampReq, then decode the reply; on a "granted"
// status invokes cb with the DER-encoded timestamp token ContentInfo,
// otherwise calls errorCb(null). The TSA URL is taken from the certificate's
// subjectInfoAccess extension.
function getStampCb(cert, hashedMessage, query, cb, errorCb, algo) {
  var tsp = rfc3161.TimeStampReq.encode(
    {
      version: 1,
      messageImprint: {
        hashAlgorithm: {
          // Default to the DSTU/GOST 34311 hash used by Ukrainian TSAs.
          algorithm: algo || "Gost34311"
        },
        hashedMessage: hashedMessage
      }
    },
    "der"
  );
  return query(
    "POST",
    cert.extension.subjectInfoAccess.link,
    {
      "Content-Type": "application/tsp-request",
      "Content-Length": tsp.length
    },
    tsp,
    function (full) {
      if (!full) return errorCb(null);
      var rtsp = rfc3161.TimeStampResp.decode(full, "der");
      if (rtsp.status.status !== "granted") {
        return errorCb(null);
      }
      // Re-encode the token as a bare DSTU CMS ContentInfo for embedding.
      cb(dstszi2010.ContentInfo.encode(rtsp.timeStampToken, "der"));
    }
  );
}

/**
 * Obtain an RFC 3161 time-stamp token for a message digest.
 * @param {Certificate} cert Certificate whose subjectInfoAccess extension provides the TSA URL.
 * @param {Buffer} hashedMessage The message digest (hash) to be time-stamped.
 * @param {function} query Transport callback (method, url, headers, body, cb).
 * @param {string} [algo] Hash algorithm identifier; defaults to "Gost34311".
 * @returns {Promise<Buffer>} Resolves with the DER-encoded timestamp token ContentInfo; rejects on failure.
 */
function getStamp(cert, hashedMessage, query, algo) {
  return new Promise((resolve, reject) =>
    getStampCb(cert, hashedMessage, query, resolve, reject, algo)
  );
}

export { getStamp };
