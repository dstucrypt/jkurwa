var Message = require('../lib/models/Message');
var Certificate = require('../lib/models/Certificate');

var Box = require('../lib/app/ctx');
var gost89 = require('node-gost89');
var fs = require('fs');

var http = require('http');
var url = require('url');

function post(queryUrL, data, cb) {
    var parsed = url.parse(queryUrL);

    var req = http.request({
        host:  parsed.host,
        path: parsed.path,
        method: 'POST',
        headers: {
            'Content-Length': data.length,
        },

    }, function (res) {
        var chunks = [];
        console.log('res', res.statusCode);
        res.on('data', function (chunk) {
            chunks.push(chunk);
        });
        res.on('end', function () {
            var full = Buffer.concat(chunks);
            fs.writeFileSync('dump-cmp', full);
            fs.writeFileSync('dump-cmp-h', full.toString('hex'));
            cb({body: full, code: res.status});
        });
    });
    req.on('error', function(e) {
        cb({code: 599});
    });
    req.write(data);
    req.end();
}

function query(box) {
    var keyids = box.keys.map(function (info) {
        return info.priv.pub().keyid(box.algo);
    });

    /* black magic here. blame eeeeeet */
    var ct = new Buffer(120);
    ct.fill(0);
    keyids[0].copy(ct, 0xC);
    (keyids[1] || keyids[0]).copy(ct, 0x2C);
    ct[0x6C] = 0x1;
    ct[0x70] = 0x1;
    ct[0x08] = 2;
    ct[0] = 0x0D;

    var msg = new Message({type: 'data', data: ct});
    return msg.as_asn1();
}

function response(resp) {
    var rmsg;
    try {
        rmsg = new Message(resp.body);
    }
    catch (e) {
        return null
    }

    if (!rmsg.info) {
        return null;
    }
    var result = rmsg.info.readInt32LE(4);
    if (result !== 1) {
        return null;
    }
    rmsg = new Message(rmsg.info.slice(8));
    var certificates = rmsg.info.certificate.map(function (certData) {
        return new Certificate(certData);
    });
    console.log('certs', certificates.map(function (cert) {
        return cert.subject;
    }));
}

function main() {
    var box = new Box({
        keys: [{
              privPath: './examples/testkey.dat',
              password: '123',
              //privPath: './FOP_key.dat',
        }],
        algo: gost89.compat.algos()
    });

    var payload = query(box);
    var servers = [
        'http://acskidd.gov.ua',
        'http://masterkey.ua',
    ];
    var idx;
    for (idx=0; idx < servers.length; idx++) {
        post(servers[idx] + '/services/cmp/', payload, response);
    }
};

main();
