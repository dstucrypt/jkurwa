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
    var sign = Buffer.from('b4f2a096a0612b72c23908f409a72b120624de995d2e4993300e51fe13b09b271e00eaa92db5abe022a5e69578223e9ff6515cb349537d3e55dc38771c92ca34', 'hex');
    var time = new Date(1542236305800);

    var cert = jk.Certificate.from_asn1(
        fs.readFileSync(__dirname + '/data/SFS_1.cer')
    );

    it('Message should sign data using privkey', ()=> {
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

    it('Message should sign hash using privkey', ()=> {
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

    it('Message should make asn1 buffer', ()=> {
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
            Buffer.from(
                fs.readFileSync(__dirname + '/data/message.hex').toString(),
                'hex'
            )
        );
    });

});

