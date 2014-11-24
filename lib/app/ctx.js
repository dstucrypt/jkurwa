'use strict';
var Keycoder = require('./keycoder'),
    Priv = require('../models/Priv'),
    Message = require('../models/Message'),
    Certificate = require('../models/Certificate'),
    pem = require('../util/pem.js'),
    deepEqual = require('deep-equal'),
    fs = require('fs');

var keycoder = new Keycoder();

var load = function load (ret, algo, keyinfo) {
    var buf = fs.readFileSync(keyinfo.path);
    var store = keycoder.parse(pem.maybe_pem(buf));
    if(store.format === 'IIT' || store.format === 'PBES2') {
        if (keyinfo.password) {
            buf = algo.storeload(store, keyinfo.pw);
            store = keycoder.parse(buf);
        } else {
            throw new Error("Specify password for keystore");
        }
    }

    if (store.format !== 'privkeys') {
        throw new Error("Cant load key from " + store.format);
    }
    ret.push({priv: store.keys[0]});
    if (store.keys[1]) {
        ret.push({priv: store.keys[1]});
    }
};

var loadCert = function (path) {
    var cbuf = fs.readFileSync(path);
    return Certificate.from_pem(cbuf);
};

var unwrappable = function (data) {
    var header = data.slice(0, 15).toString();
    if (header.substr(0, 14) === 'TRANSPORTABLE\u0000') {
        return true;
    }
    if (header.substr(3, 7) === '_CRYPT\u0000') {
        return true;
    }
    if (header.substr(3, 6) === '_SIGN\u0000') {
        return true;
    }
    if (header.substr(0, 10) === 'CERTCRYPT\u0000') {
        return true;
    }
    return false;
};

var merge = function (obj1, obj2) {
    var ret = {};
    [obj1, obj2].map(function (obj) {
        Object.keys(obj).map(function (key) {
            ret[key] = obj[key];
        });
    });
    return ret;
};

var Box  = function Box (opts) {
    opts = opts || {};
    var keys = [];
    if (typeof opts.keys === 'string') {
        opts.keys = [{path: opts.keys}];
    }
    if (typeof opts.cert === 'string') {
        opts.cert = [opts.cert];
    }
    opts.cert = opts.cert || [];

    opts.keys.map(load.bind(null, keys, opts.algo));
    this.keys = keys;
    this.certCache = opts.cert.map(loadCert);
    this.algo = merge(opts.algo, {lookup: this.certLookup.bind(this)});

    this.bindCerts();
};

Box.prototype.bindCerts = function bindCerts () {
    var idx, cidx;
    var cert;
    var key;
    for (cidx = 0; cidx < this.keys.length; cidx++) {
        key = this.keys[cidx].priv;
        for (idx = 0; idx < this.certCache.length; idx++) {
            cert = this.certCache[idx];
            if (key.pub_match(cert.pubkey)) {
                this.keys[cidx].cert = cert;
                break;
            }
        }
        if (!this.keys[cidx].cert) {
            console.log("Certificate for key", key.pub_compress().toString(), "not loaded");
        }
    }
};

Box.prototype.certLookup = function certLookup (query, role, addPossible) {
    var idx, cert;
    var certs = this.certCache.concat(addPossible || []);
    for (idx = 0; idx < certs.length; idx++) {
        cert = certs[idx];
        if (deepEqual(query, cert.nameSerial())) {
            return cert;
        }
    }
};


Box.prototype.keyLookup = function keyLookup (query) {
    var idx, key;

    for (idx = 0; idx < this.keys.length; idx ++) {
        key = this.keys[idx];
        if (key.cert && deepEqual(query, key.cert.nameSerial())) {
            return key.priv;
        }
    }
};

Box.prototype.sign = function sign (data, role) {
    var key = this.keyFor('sign', role);
    var msg = new Message({
        type: 'signedData',
        cert: key.cert,
        data: data,
        signer: key.priv,
        hash: this.algo.hash,
    });
    return msg;
};


Box.prototype.encrypt = function encrypt (data, role, forCert) {
    if (forCert === undefined) {
        throw new Error("No recipient specified for encryption");
    }
    var key = this.keyFor('encrypt', role);
    var msg_e = new Message({
        type: 'envelopedData',
        cert: key.cert,
        toCert: forCert,
        data: data,
        crypter: key.priv,
        algo: this.algo,
    });
    return msg_e;
};


Box.prototype.keyFor = function keyFor (op, role) {
    if (op === 'sign') {
        return this.keys[0];
    }

    if (op === 'encrypt') {
        return this.keys[1] || this.keys[0];
    }

    throw new Error("unknown error for " + op);
};

Box.prototype.pipe = function pipe (data, commands, opts) {
    var idx, cmd, msg, cert;
    for (idx=0; idx < commands.length; idx++) {
        cmd = commands[idx];
        if (typeof cmd === 'string') {
            cmd = {op: cmd};
        }
        if (cmd.op === undefined) {
            throw new Error("Broken pipeline element", cmd);
        }
        cert = cmd.forCert;
        if (typeof cert === 'string') {
            cert = Certificate.from_pem(cert);
        }
        msg = this[cmd.op](data, cmd.role, cert);
        data = msg.as_transport(idx === (commands.length - 1) ? opts : cmd.addCert);
    }

    return data;
};

Box.prototype.unwrap = function (data) {
    var msg;
    var x;
    var info = {pipe: []};
    var signed;
    while (unwrappable(data)) {
        msg = new Message(data);
        if (msg.type === 'signedData') {
            signed = msg.verify(this.algo.hash);
            if (signed !== true) {
                return {'error': 'ESIGN', content: data};
            }
            x = msg.signer();
            data = msg.info.contentInfo.content;
            info.pipe.push({
                signed: signed,
                cert: {
                    subject: x.subject,
                    issuer: x.issuer,
                    extension: x.extension,
                    valid: x.valid,
                },
                transport: msg.transport,
            });
        }
        if (msg.type === 'envelopedData') {
            info.pipe.push({
                enc: true,
                transport: msg.transport,
            });
            data = msg.decrypt(this.keyLookup.bind(this), this.algo);
        }
    }
    info.content = data;
    return info;
};

module.exports = Box;
