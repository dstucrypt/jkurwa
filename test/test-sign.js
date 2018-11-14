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
    var sign = Buffer.from('e45fe541d047ae546825f91db53906306024ad12fcbe8185b9fce2e615e52b2084dad217d37612ee8761da493db0c4570ac5d323c649b1c83093897536b23a5b', 'hex');
    var time = 1540236305;

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
        assert.equal(time * 1000, message.pattrs.signingTime);
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

    it('should check digest and signing time against certificate validity range', function () {
        var message = new Message(
            fs.readFileSync(__dirname + '/data/message.p7')
        );
        assert.equal(message.verifyAttrs(algo.hash), true);
    });

    it('should fail attribute check if time is not specified (expired cert)', function() {
        var message = new Message({
            type: 'signedData',
            cert: cert,
            data: data,
            hash: algo.hash,
            signer: key1,
        });
        assert.equal(message.verifyAttrs(algo.hash), false);
    });

    it('should fail attribute check if data does not match digest', function() {
        var message = new Message({
            type: 'signedData',
            cert: cert,
            data: data,
            dataHash: Buffer.from('12345678901234567890123456789098'),
            hash: algo.hash,
            signTime: time,
            signer: key1,
        });
        assert.equal(message.verifyAttrs(algo.hash), false);
    });

    it('should fail verification (pubkey does not match certificate)', function () {
        var message = new Message(
            fs.readFileSync(__dirname + '/data/message.p7')
        );
        assert.equal(message.verify(algo.hash), false);
    });

});

