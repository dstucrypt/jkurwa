var fs = require('fs');
var rfc2560 = require('../lib/spec/rfc2560-ocsp');
var Certificate = require('../lib/models/Certificate');
var http = require('http');
var url = require('url');
var gost89 = require('gost89');

function loadCert (path) {
    var buf = fs.readFileSync(path);
    return Certificate.from_asn1(buf);
}

function main() {
    var cert = loadCert(process.argv[2]);
    var certSpec = {
        hashAlgorithm: {
            algorithm: 'Gost34311',
        },
        issuerNameHash: gost89.gosthash(cert.name_asn1()),
        issuerKeyHash: cert.extension.authorityKeyIdentifier.slice(4),
        serialNumber: cert.serial,
    };
    var ocsp = rfc2560.OCSPRequest.encode({
        tbsRequest: {
            requestList: [{
                reqCert: certSpec,
            }],
            requestExtensions: [{
                extnID: 'OCSPNonce',
                extnValue: new Buffer(20),
            }],
        },
    }, 'der');
    var parsed = url.parse(cert.extension.ocsp);
    var req = http.request({
        host:  parsed.host,
        path: parsed.path,
        headers: {
            'Content-Type': 'application/ocsp-request',
            'Content-Length': ocsp.length,
        },
        method: 'POST'
    }, function (res) {
        var chunks = [];
        res.on('data', function (chunk) {
            chunks.push(chunk);
        });
        res.on('end', function () {
            var full = Buffer.concat(chunks);
            var rocsp = rfc2560.OCSPResponse.decode(full, 'der');
            var rocspbody = rfc2560.BasicOCSPResponse.decode(rocsp.responseBytes.response, 'der');
            console.log('resp body', rocspbody);
        });
    });
    req.on('error', function(e) {
          console.log('problem with request: ' + e.message);
    });
    req.write(ocsp);
    req.end();
};

main();
