const cades = require("../spec/rfc5126-cades.js");
const rfc2560 = require("../spec/rfc2560-ocsp");
const Certificate = require("./Certificate");

class OCSPError extends Error {}

function encodeSpec(cert, serial, hashFn) {
  return (certSpec = {
    hashAlgorithm: {
      algorithm: hashFn.algo || "Gost34311"
    },
    issuerNameHash: hashFn(cert.name_asn1()),
    issuerKeyHash: cert.extension.authorityKeyIdentifier,
    serialNumber: serial
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

class Ref {
  constructor(ob) {
    this.ob = ob;
  }
}

Ref.toCades = function(list) {
  const ob = list.map(iter =>
    iter.length ? { ocspids: { ocspResponses: iter.map(ref => ref.ob) } } : {}
  );
  return cades.RevocationRefs.encode(ob, "der");
};

Ref.fromCades = function(raw) {
  const response = cades.RevocationRefs.decode(raw, "der");
  return response.map(ob =>
    ((ob.ocspids && ob.ocspids.ocspResponses) || []).map(iter => new Ref(iter))
  );
};

class OcspResponse {
  constructor(basic) {
    this.ob = basic;
  }

  makeRef(ctx) {
    return new Ref({
      ocspIdentifier: {
        ocspResponderID: this.ob.tbsResponseData.responderID,
        producedAt: this.ob.tbsResponseData.producedAt
      },
      ocspRepHash: {
        hashAlgorithm: {
          algorithm: ctx.hashFn.algo || "Gost34311"
        },
        hashValue: ctx.hashFn(this.to_asn1())
      }
    });
  }

  matches(cert, serial, ctx) {
    const response = this.ob;
    const [status] = response.tbsResponseData.responses;

    const spec = OcspResponse.encodeSpec(cert, serial, ctx.hashFn);
    const specData = rfc2560.CertID.encode(spec);
    const respSpecData = rfc2560.CertID.encode(status.certID);
    return specData.equals(respSpecData);
  }

  verify(ctx, cert, serial, nonce, isOcspStamp) {
    const response = this.ob;
    const [status] = response.tbsResponseData.responses;

    const responderRDN = makeResponderRDN(response.tbsResponseData.responderID);
    const responder = findByName(responderRDN, response.certs);
    const responderOk = responder.verify(
      { time: status.thisUpdate, usage: "ocspSigning" },
      { Dstu4145le: ctx.hashFn },
      ctx.lookupCA
    );
    if (!responderOk) {
      throw new OCSPError();
    }

    const signedBySame = responder.extension.authorityKeyIdentifier.equals(
      cert.extension.authorityKeyIdentifier
    );
    if (!signedBySame) {
      throw new OCSPError();
    }

    const tbs = rfc2560.ResponseData.encode(response.tbsResponseData, "der");
    const isValid = responder
      .pubkey_unpack()
      .verify(ctx.hashFn(tbs), response.signature.data);
    if (!isValid) {
      throw new OCSPError();
    }

    if (!isOcspStamp) {
      checkNonce(response.tbsResponseData, nonce);
    }

    const spec = OcspResponse.encodeSpec(cert, serial, ctx.hashFn);
    const specData = rfc2560.CertID.encode(spec);
    const respSpecData = rfc2560.CertID.encode(status.certID);
    if (!specData.equals(respSpecData)) {
      throw new OCSPError();
    }

    return {
      requestOk: true,
      statusOk: status.certStatus.type === "good",
      time: status.thisUpdate,
      isOcspStamp,
      cert: findByIssuerSerial(response.certs, cert.issuerDN(), serial)
    };
  }

  to_asn1() {
    return rfc2560.BasicOCSPResponse.encode(this.ob, "der");
  }
}

OcspResponse.fromBasic = function(raw) {
  return new OcspResponse(rfc2560.BasicOCSPResponse.decode(raw, "der"));
};

OcspResponse.fromCades = function(raw) {
  const response = cades.RevocationValues.decode(raw, "der");
  return response.ocspVals.map(ob => new OcspResponse(ob));
};

OcspResponse.toCades = function(list) {
  const ocspVals = list.map(iter => iter.ob);
  return cades.RevocationValues.encode({ ocspVals }, "der");
};

OcspResponse.encodeSpec = encodeSpec;

OcspResponse.Ref = Ref;

module.exports = OcspResponse;
