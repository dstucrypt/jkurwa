'use strict';
var Keycoder = require('./keycoder'),
    Priv = require('../models/Priv'),
    Message = require('../models/Message'),
    Certificate = require('../models/Certificate'),
    pem = require('../util/pem.js'),
    fs = require('fs');

var keycoder = new Keycoder();

var load = function load (ret, algo, keyinfo) {

    if (typeof keyinfo.privPath === 'string') {
        var buf = fs.readFileSync(keyinfo.privPath);
        var store = keycoder.parse(pem.maybe_pem(buf));
        if(store.format === 'IIT' || store.format === 'PBES2') {
            if (keyinfo.password) {
                buf = algo.storeload(store, keyinfo.password);
                store = keycoder.parse(buf);
            } else {
                throw new Error("Specify password for keystore");
            }
        }

        if (store.format !== 'privkeys') {
            throw new Error("Cant load key from " + store.format);
        }
        var paths;
        if (typeof keyinfo.certPath === 'string') {
            paths = [keyinfo.certPath];
        } else {
            paths = keyinfo.certPath || [];
        }
        var certs = paths.map(function (path) {
            var cbuf = fs.readFileSync(path);
            return Certificate.from_pem(cbuf);
        });
        ret.push({priv: store.keys[0], cert: certs[0]});
        if (store.keys[1]) {
            ret.push({priv: store.keys[1], cert: certs[1]});
        }
        return;
    }

    throw new Error("Cant load key from " + keyinfo);
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

var Box  = function Box (opts) {
    opts = opts || {};
    if (opts.keys) {
        var keys = [];
        opts.keys.map(load.bind(null, keys, opts.algo));
        this.keys = keys;
    }
    
    this.algo = opts.algo || {};
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
    var key;
    while (unwrappable(data)) {
        msg = new Message(data);
        if (msg.type === 'signedData') {
            signed = msg.verify(this.algo.hash);
            if (signed !== true) {
                info.pipe.push({
                    broken_sign: true,
                    error: "ESIGN",
                });
                info.error = "ESIGN";
                break;
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
            key = this.keyFor('encrypt');
            if (key === undefined || key.priv === undefined) {
                info.pipe.push({
                    enc: true,
                    error: "ENOKEY"
                });
                info.error = "ENOKEY";
                break;
            }
            info.pipe.push({
                enc: true,
                transport: msg.transport,
            });
            data = msg.decrypt(key.priv, this.algo);
        }
    }
    info.content = data;
    return info;
};

module.exports = Box;
