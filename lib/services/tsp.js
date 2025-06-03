import rfc3161 from "../spec/rfc3161-tsp";
import Certificate from "../models/Certificate";
import gost89 from "gost89";
import dstszi2010 from "../spec/dstszi2010";

function getStampCb(cert, hashedMessage, query, cb, errorCb) {
  var tsp = rfc3161.TimeStampReq.encode(
    {
      version: 1,
      messageImprint: {
        hashAlgorithm: {
          algorithm: "Gost34311"
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
    function(full) {
      if (!full) return errorCb(null);
      var rtsp = rfc3161.TimeStampResp.decode(full, "der");
      if (rtsp.status.status !== "granted") {
        return errorCb(null);
      }
      cb(dstszi2010.ContentInfo.encode(rtsp.timeStampToken, "der"));
    }
  );
}

function getStamp(cert, hashedMessage, query) {
  return new Promise((resolve, reject) =>
    getStampCb(cert, hashedMessage, query, resolve, reject)
  );
}

export { getStamp };
