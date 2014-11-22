'use strict';
var jk = require('../..'),
    Priv = require('../models/Priv'),
    Message = require('../models/Message'),
    Certificate = require('../models/Certificate'),
    fs = require('fs');

var keycoder = new jk.Keycoder();

var load = function load (ret, keyinfo) {

    if (typeof keyinfo.privPath === 'string' && 
        (typeof keyinfo.certPath === 'string' || 
         Array.isArray(keyinfo.certPath))) {
        var buf = fs.readFileSync(keyinfo.privPath);
        var store = keycoder.parse(buf);
        if (store.format !== 'privkeys') {
            throw new Error("Cant load " + store.format + " without password");
        }
        var paths;
        if (typeof keyinfo.certPath === 'string') {
            paths = [keyinfo.certPath];
        } else {
            paths = keyinfo.certPath;
        }
        var certs = paths.map(function (path) {
            var cbuf = fs.readFileSync(path);
            return Certificate.from_asn1(cbuf);
        });
        ret.push({priv: store.keys[0], cert: certs[0]});
        if (store.keys[1] && certs[1]) {
            ret.push({priv: store.keys[1], cert: certs[1]});
        }
        return;
    }

    throw new Error("Cant load key from " + keyinfo);
};

var Box  = function Box (opts) {
    opts = opts || {};
    if (opts.keys) {
        var keys = [];
        opts.keys.map(load.bind(null, keys));
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
    var idx, cmd, msg;
    for (idx=0; idx < commands.length; idx++) {
        cmd = commands[idx];
        if (typeof cmd === 'string') {
            cmd = {op: cmd};
        }
        if (cmd.op === undefined) {
            throw new Error("Broken pipeline element", cmd);
        }
        msg = this[cmd.op](data, cmd.role, cmd.forCert);
        data = msg.as_transport(idx === (commands.length - 1) ? opts : cmd.addCert);
    }

    return data;
};

module.exports = Box;
