var jksreader = require('jksreader'),
    jk = require('../lib'),
    gost89 = require('gost89'),
    Priv = require('../lib/models/Priv'),
    Message = require('../lib/models/Message'),
    Certificate = require('../lib/models/Certificate'),
    transport = require('../lib/util/transport'),
    pem = require('../lib/util/pem.js'),
    tspService = require('../lib/services/tsp'),
    keys = require('./data/keys'),
    assert = require('assert'),
    fs = require('fs');

var NOT_RANDOM_32 = Buffer.from(
    '12345678901234567890123456789012'
);
try {
    crypto.getRandomValues;
} catch (e) {
    crypto = {
        // Moch random only for testing purposes.
        // SHOULD NOT BE USED IN REAL CODE.
        getRandomValues: function (buf) {
            return NOT_RANDOM_32;
        }
    }
}

describe('Signed Message', function () {
    var store = jk.guess_parse(keys.PEM_KEY_RAW);
    var [key1, key2] = store.keys;
    var data = Buffer.from('123');
    var algo = gost89.compat.algos();
    var dataHash = algo.hash(data);
    var sign = Buffer.from('77ee7c58f828f2d8240736b59d786558b693e26221e6a696856c85567a7e9263d72d7380c37533ed81c1d19f00f0bc4a03cb6c309d8053baf9eba2caa243ec1d', 'hex');
    var time = 1542236305;

    var cert = jk.Certificate.from_asn1(
        fs.readFileSync(__dirname + '/data/SFS_1.cer')
    );

    it('should sign data using privkey', function() {
        var message = new Message({
            type: 'signedData',
            cert: cert,
            data: data,
            hash: algo.hash,
            signTime: time,
            signer: key1,
        });
        assert.equal(message.wrap.content.contentInfo.content, data);
        var [signInfo] = message.wrap.content.signerInfos;
        assert.deepEqual(signInfo.encryptedDigest, sign);
    });

    it('should sign hash using privkey', function() {
        var message = new Message({
            type: 'signedData',
            cert: cert,
            dataHash: dataHash,
            hash: algo.hash,
            signTime: time,
            signer: key1,
        });
        assert.equal(message.wrap.content.contentInfo.content, undefined);
        var [signInfo] = message.wrap.content.signerInfos;
        assert.deepEqual(signInfo.encryptedDigest, sign);
    });

    it('should make asn1 buffer', function() {
        var message = new Message({
            type: 'signedData',
            cert: cert,
            data: data,
            hash: algo.hash,
            signTime: time,
            signer: key1,
        });

        assert.deepEqual(
            message.as_asn1(),
            fs.readFileSync(__dirname + '/data/message.p7')
        );
    });

    it('should parse message from asn1 buffer', function() {
        var message = new Message(
            fs.readFileSync(__dirname + '/data/message.p7')
        );
        var [signInfo] = message.wrap.content.signerInfos;
        assert.deepEqual(signInfo.encryptedDigest, sign);
        assert.deepEqual(message.wrap.content.contentInfo.content, data);
        var [signCert] = message.wrap.content.certificate;
        assert.deepEqual(new jk.Certificate(signCert).as_dict(), cert.as_dict());
        assert.equal(time * 1000, message.pattrs.signingTime);
    });

});

