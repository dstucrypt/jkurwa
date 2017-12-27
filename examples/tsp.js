var fs = require('fs');
var rfc3161 = require('../lib/spec/rfc3161-tsp');
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
    var tsp = rfc3161.TimeStampReq.encode({
        version: 1,
        messageImprint: {
          hashAlgorithm: {
            algorithm: 'Gost34311',
          },
          hashedMessage: new Buffer('313EEE9320AF932E719C7ECF3249C03699F6F5FFFB7D87653EB84459C0D943F2', 'hex'),
        },
    }, 'der');
    var parsed = url.parse(cert.extension.tsp);
    var req = http.request({
        host:  parsed.host,
        path: parsed.path,
        headers: {
            'Content-Type': 'application/tsp-request',
            'Content-Length': tsp.length,
        },
        method: 'POST'
    }, function (res) {
        var chunks = [];
        res.on('data', function (chunk) {
            chunks.push(chunk);
        });
        res.on('end', function () {
            var full = Buffer.concat(chunks);
            var rtsp = rfc3161.TimeStampResp.decode(full, 'der');
            if (rtsp.status.status !== 'granted') {
                console.log('oops');
                return;
            }
            rtsp = rfc3161.TSTInfo.decode(rtsp.timeStampToken.content.contentInfo.content);
            console.log('resp body', rtsp);
        });
    });
    req.on('error', function(e) {
          console.error('problem with request: ' + e.message);
    });
    req.write(tsp);
    req.end();
};

main();
