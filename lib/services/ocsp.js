var fs = require("fs");
var rfc2560 = require("../spec/rfc2560-ocsp");
var Certificate = require("../models/Certificate");

class OCSPError extends Error {}

function loadCert(path) {
  var buf = fs.readFileSync(path);
  return Certificate.from_asn1(buf);
}

function encodeSpec(cert, serial, hashFn) {
  return (certSpec = {
    hashAlgorithm: {
      algorithm: "Gost34311"
    },
    issuerNameHash: hashFn(cert.name_asn1()),
    issuerKeyHash: cert.extension.authorityKeyIdentifier.slice(4),
    serialNumber: serial
  });
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
    function(full) {
      var rocsp = rfc2560.OCSPResponse.decode(full, "der");
      if (rocsp.responseStatus !== "successful") {
        cb(null);
      }
      cb(rfc2560.BasicOCSPResponse.decode(rocsp.responseBytes.response, "der"));
    }
  );
}

function request(...args) {
  return new Promise((resolve, reject) => {
    requestCB(...args, ret => (ret ? resolve(ret) : reject(ret)));
  });
}

function makeResponderRDN({ type, value }) {
  if (type === "byName") {
    return Certificate.formatDN(value.value);
  }
  throw new OCSPError();
}

function findByName(query, list) {
  for (let cert of list) {
    if (Certificate.formatDN(cert.tbsCertificate.subject.value) === query) {
      return new Certificate(cert);
    }
  }
  throw new OCSPError();
}

function checkNonce(tbs, nonce) {
  const ext = tbs.responseExtensions.find(part => part.extnID === "OCSPNonce");
  if (!ext || !ext.extnValue.equals(nonce)) {
    throw new OCSPError();
  }
}

function findByIssuerSerial(list, issuerDN, serial) {
  return list.find(
    iter =>
      Certificate.formatDN(iter.tbsCertificate.issuer.value) === issuerDN &&
      iter.tbsCertificate.serialNumber.eq(serial)
  );
}

async function lookup(cert, serial, nonce, query, lookupCA, hashFn) {
  const spec = encodeSpec(cert, serial, hashFn);
  const response = await request(cert.extension.ocsp, spec, nonce, query);
  const [status] = response.tbsResponseData.responses;

  const responderRDN = makeResponderRDN(response.tbsResponseData.responderID);
  const responder = findByName(responderRDN, response.certs);
  const responderOk = responder.verify(
    { time: status.thisUpdate, usage: "ocspSigning" },
    { Dstu4145le: hashFn },
    lookupCA
  );
  if (!responderOk) {
    throw new OCSPError();
  }

  const tbs = rfc2560.ResponseData.encode(response.tbsResponseData, "der");
  const isValid = responder
    .pubkey_unpack()
    .verify(hashFn(tbs), response.signature.data);
  if (!isValid) {
    throw new OCSPError();
  }

  checkNonce(response.tbsResponseData, nonce);

  const specData = rfc2560.CertID.encode(spec);
  const respSpecData = rfc2560.CertID.encode(status.certID);
  if (!specData.equals(respSpecData)) {
    throw new OCSPError();
  }

  return {
    requestOk: true,
    statusOk: status.certStatus.type === "good",
    time: status.thisUpdate,
    cert: findByIssuerSerial(response.certs, cert.issuerDN(), serial)
  };
}
module.exports = { lookup };
