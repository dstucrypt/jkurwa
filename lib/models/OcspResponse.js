/*
 * OCSP (RFC 2560) response model for the DSTU 4145 PKI, with CAdES
 * (RFC 5126) revocation reference/value packaging.
 *
 * An OcspResponse wraps a BasicOCSPResponse and can:
 *   - build the CertID that identifies which certificate a status refers to;
 *   - verify a response end-to-end (locate and validate the responder cert,
 *     check the responder shares the target's CA, verify the DSTU signature
 *     over the response data, check the request nonce, and confirm the CertID
 *     matches the certificate being queried);
 *   - build a CAdES OcspResponsesID reference (responder id + producedAt +
 *     hash of the response) and encode/decode revocation refs and values.
 */
import * as cades from "../spec/rfc5126-cades.js";
import * as rfc2560 from "../spec/rfc2560-ocsp.js";
import Certificate from "./Certificate.js";

class OCSPError extends Error {}

/**
 * Build an OCSP CertID for a certificate: the request/response key that ties a
 * status to a specific certificate via issuer name hash, issuer key hash and
 * serial number. Defaults to the GOST 34.311 hash used by DSTU.
 * @param {Certificate} cert the target certificate being queried
 * @param {Object} serial the certificate serial number
 * @param {function} hashFn hash function (with optional `.algo` OID name)
 * @returns {Object} CertID structure ready for encoding
 */
function encodeSpec(cert, serial, hashFn) {
  return {
    hashAlgorithm: {
      algorithm: hashFn.algo || "Gost34311"
    },
    // issuerNameHash is over the DER of the issuer Name; issuerKeyHash reuses
    // the target's authorityKeyIdentifier (the issuer's subject key id).
    issuerNameHash: hashFn(cert.name_asn1()),
    issuerKeyHash: cert.extension.authorityKeyIdentifier,
    serialNumber: serial
  };
}

/**
 * Locate the responder certificate by subject DN (responderID byName form).
 * @param {Object} query decoded Name to match against subjects
 * @param {Array<Object>} list decoded certificates bundled in the response
 * @returns {Certificate} matching responder certificate
 * @throws {OCSPError} when no certificate matches
 */
function findByName(query, list) {
  const rdn = Certificate.formatDN(query.value);
  for (let cert of list) {
    if (Certificate.formatDN(cert.tbsCertificate.subject.value) === rdn) {
      return new Certificate(cert);
    }
  }
  throw new OCSPError();
}

/**
 * Locate the responder certificate by subject key identifier (responderID
 * byKey form). Slices the 2-byte OCTET STRING TLV prefix off the stored
 * extension value before comparing to the queried key hash.
 * @param {Buffer} query raw key-identifier bytes to match
 * @param {Array<Object>} list decoded certificates bundled in the response
 * @returns {Certificate} matching responder certificate
 * @throws {OCSPError} when no certificate matches
 */
function findByKey(query, list) {
  for (let cert of list) {
    const keyIdExt = cert.tbsCertificate.extensions.find(
      e => e.extnID === "subjectKeyIdentifier"
    );
    if (!keyIdExt) {
      continue;
    }
    if (keyIdExt.extnValue.slice(2).equals(query)) {
      return new Certificate(cert);
    }
  }
  throw new OCSPError();
}

/**
 * Confirm the response echoes the request nonce, preventing replay of a stale
 * OCSP response.
 * @param {Object} tbs decoded ResponseData (with responseExtensions)
 * @param {Buffer} nonce the nonce sent in the request
 * @throws {OCSPError} when the nonce extension is absent or mismatched
 */
function checkNonce(tbs, nonce) {
  const ext = tbs.responseExtensions.find(part => part.extnID === "OCSPNonce");
  if (!ext || !ext.extnValue.equals(nonce)) {
    throw new OCSPError();
  }
}

/**
 * Find the queried certificate inside the response's certificate bundle by
 * issuer DN and serial number.
 * @param {Array<Object>} list decoded certificates from the response
 * @param {string} issuerDN formatted issuer DN to match
 * @param {Object} serial serial number to match
 * @returns {Object|undefined} the matching decoded certificate, if present
 */
function findByIssuerSerial(list, issuerDN, serial) {
  return list.find(
    iter =>
      Certificate.formatDN(iter.tbsCertificate.issuer.value) === issuerDN &&
      iter.tbsCertificate.serialNumber.eq(serial)
  );
}

/**
 * A CAdES OcspResponsesID reference to an OCSP response (responder id,
 * producedAt time and a hash of the response), used inside RevocationRefs.
 */
class Ref {
  /**
   * @param {Object} ob decoded OcspResponsesID structure
   */
  constructor(ob) {
    this.ob = ob;
  }
}

/**
 * Encode a per-signer list of OCSP references as a CAdES RevocationRefs value.
 * Each signer maps to an ocspids group; empty groups encode as an empty entry.
 * @param {Array<Array<Ref>>} list references grouped per signer
 * @returns {Buffer} DER-encoded RevocationRefs
 */
Ref.toCades = function (list) {
  const ob = list.map(iter =>
    iter.length ? { ocspids: { ocspResponses: iter.map(ref => ref.ob) } } : {}
  );
  return cades.RevocationRefs.encode(ob, "der");
};

/**
 * Decode CAdES RevocationRefs back into a per-signer list of Ref objects.
 * @param {Buffer} raw DER-encoded RevocationRefs
 * @returns {Array<Array<Ref>>} references grouped per signer
 */
Ref.fromCades = function (raw) {
  const response = cades.RevocationRefs.decode(raw, "der");
  return response.map(ob =>
    ((ob.ocspids && ob.ocspids.ocspResponses) || []).map(iter => new Ref(iter))
  );
};

class OcspResponse {
  /**
   * @param {Object} basic decoded BasicOCSPResponse
   */
  constructor(basic) {
    this.ob = basic;
  }

  /**
   * Build a CAdES reference to this response: the responder id and producedAt
   * time plus a hash over the encoded response.
   * @param {{hashFn: function}} ctx hash context (hashFn with optional `.algo`)
   * @returns {Ref} the CAdES OcspResponsesID reference
   */
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

  /**
   * Test whether this response's single status entry refers to the given
   * certificate/serial, by comparing the encoded CertIDs byte-for-byte.
   * @param {Certificate} cert the target certificate
   * @param {Object} serial the certificate serial number
   * @param {{hashFn: function}} ctx hash context
   * @returns {boolean} true when the CertIDs match
   */
  matches(cert, serial, ctx) {
    const response = this.ob;
    const [status] = response.tbsResponseData.responses;

    const spec = OcspResponse.encodeSpec(cert, serial, ctx.hashFn);
    const specData = rfc2560.CertID.encode(spec);
    const respSpecData = rfc2560.CertID.encode(status.certID);
    return specData.equals(respSpecData);
  }

  /**
   * Fully validate an OCSP response for a certificate. Steps:
   *   1. resolve the responder cert from the bundle by responderID (byName or
   *      byKey);
   *   2. verify that responder cert for ocspSigning usage as of thisUpdate;
   *   3. require the responder to share the target's CA (same
   *      authorityKeyIdentifier), so the OCSP delegation is legitimate;
   *   4. verify the DSTU signature over the ResponseData;
   *   5. unless this is an archival OCSP stamp, check the request nonce;
   *   6. confirm the response CertID matches the queried certificate.
   * Throws on any failure; otherwise returns the parsed status.
   * @param {Object} ctx context: hashFn, optional hashVerify, lookupCA resolver
   * @param {Certificate} cert the certificate whose status was requested
   * @param {Object} serial the certificate serial number
   * @param {Buffer} nonce nonce sent in the request
   * @param {boolean} isOcspStamp true for a stored/archival stamp (skips nonce)
   * @returns {{requestOk: boolean, statusOk: boolean, time: *, isOcspStamp: boolean, cert: Object}}
   * @throws {OCSPError} on any validation failure
   */
  verify(ctx, cert, serial, nonce, isOcspStamp) {
    const response = this.ob;
    const [status] = response.tbsResponseData.responses;

    const responderID = response.tbsResponseData.responderID;
    const queryFn = {
      byName: query => findByName(query, response.certs),
      byKey: query => findByKey(query, response.certs)
    }[responderID.type];
    if (!queryFn) {
      throw new OCSPError();
    }
    const responder = queryFn(responderID.value);
    // Validate the responder certificate itself, requiring the ocspSigning EKU
    // and evaluating validity at the response's thisUpdate time.
    const responderOk = responder.verify(
      { time: status.thisUpdate, usage: "ocspSigning" },
      ctx.hashVerify || { Dstu4145le: ctx.hashFn },
      ctx.lookupCA
    );
    if (!responderOk) {
      throw new OCSPError();
    }

    // The responder must be issued by the same CA as the target certificate;
    // otherwise it has no authority to speak to that certificate's status.
    const signedBySame = responder.extension.authorityKeyIdentifier.equals(
      cert.extension.authorityKeyIdentifier
    );
    if (!signedBySame) {
      throw new OCSPError();
    }

    // Verify the DSTU 4145 signature over the DER-encoded ResponseData.
    const tbs = rfc2560.ResponseData.encode(response.tbsResponseData, "der");
    const isValid = responder
      .pubkey_unpack()
      .verify(ctx.hashFn(tbs), response.signature.data);
    if (!isValid) {
      throw new OCSPError();
    }

    // Archival stamps have no live request, so nonce checking only applies to
    // fresh responses.
    if (!isOcspStamp) {
      checkNonce(response.tbsResponseData, nonce);
    }

    // Ensure the response actually answers about the certificate we asked
    // about by comparing the reconstructed CertID with the response's.
    const spec = OcspResponse.encodeSpec(cert, serial, ctx.hashFn);
    const specData = rfc2560.CertID.encode(spec);
    const respSpecData = rfc2560.CertID.encode(status.certID);
    if (!specData.equals(respSpecData)) {
      throw new OCSPError();
    }

    return {
      requestOk: true,
      // certStatus is a CHOICE; "good" means not revoked (vs "revoked"/"unknown").
      statusOk: status.certStatus.type === "good",
      time: status.thisUpdate,
      isOcspStamp,
      cert: findByIssuerSerial(response.certs, cert.issuerDN(), serial)
    };
  }

  /**
   * @returns {Buffer} DER-encoded BasicOCSPResponse
   */
  to_asn1() {
    return rfc2560.BasicOCSPResponse.encode(this.ob, "der");
  }
}

/**
 * Decode a raw BasicOCSPResponse into an OcspResponse.
 * @param {Buffer} raw DER-encoded BasicOCSPResponse
 * @returns {OcspResponse}
 */
OcspResponse.fromBasic = function (raw) {
  return new OcspResponse(rfc2560.BasicOCSPResponse.decode(raw, "der"));
};

/**
 * Decode a CAdES RevocationValues blob into its list of OCSP responses.
 * @param {Buffer} raw DER-encoded RevocationValues
 * @returns {Array<OcspResponse>}
 */
OcspResponse.fromCades = function (raw) {
  const response = cades.RevocationValues.decode(raw, "der");
  return response.ocspVals.map(ob => new OcspResponse(ob));
};

/**
 * Encode a list of OCSP responses as a CAdES RevocationValues blob.
 * @param {Array<OcspResponse>} list responses to bundle
 * @returns {Buffer} DER-encoded RevocationValues
 */
OcspResponse.toCades = function (list) {
  const ocspVals = list.map(iter => iter.ob);
  return cades.RevocationValues.encode({ ocspVals }, "der");
};

OcspResponse.encodeSpec = encodeSpec;

OcspResponse.Ref = Ref;

export default OcspResponse;
