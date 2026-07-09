import rfc3161 from "../spec/rfc3161-tsp.js";
import Certificate from "../models/Certificate.js";
import gost89 from "gost89";
import * as dstszi2010 from "../spec/dstszi2010.js";

function getStampCb(cert, hashedMessage, query, cb, errorCb, algo) {
  var tsp = rfc3161.TimeStampReq.encode(
    {
      version: 1,
      messageImprint: {
        hashAlgorithm: {
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
      cb(dstszi2010.ContentInfo.encode(rtsp.timeStampToken, "der"));
    }
  );
}

function getStamp(cert, hashedMessage, query, algo) {
  return new Promise((resolve, reject) =>
    getStampCb(cert, hashedMessage, query, resolve, reject, algo)
  );
}

export { getStamp };
