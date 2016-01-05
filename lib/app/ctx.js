'use strict';
var Priv = require('../models/Priv'),
    Message = require('../models/Message'),
    Certificate = require('../models/Certificate'),
    transport = require('../util/transport'),
    pem = require('../util/pem.js'),
    fs = require('fs');

var load = function load (ret, algo, keyinfo) {
    if ((keyinfo.priv && keyinfo.priv.type  === 'Priv') ||
        (keyinfo.cert && keyinfo.cert.format === 'x509')) {
        ret({priv: keyinfo.priv});
        ret({cert: keyinfo.cert});
        return;
    }
    if (keyinfo.privPem || keyinfo.certPem) {
        ret({
            priv: (keyinfo.privPem !== undefined) ? Priv.from_pem(keyinfo.privPem) : undefined,
        });
        ret({
            cert: (keyinfo.certPem !== undefined) ? Certificate.from_pem(keyinfo.certPem) : undefined,
        });
        return;
    }

    if (typeof keyinfo.privPath === 'string') {
        var buf = fs.readFileSync(keyinfo.privPath);
        var store;
        try {
            store = Priv.from_protected(buf, keyinfo.password, algo);
        } catch (ignore) {
            throw new Error("Cant load key from store");
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
        var idx;
        for (idx=0; idx < certs.length; idx++) {
            ret({cert: certs[idx]});
        }
        for (idx=0; idx < store.keys.length; idx++) {
            ret({priv: store.keys[idx]});
        }
        return;
    }

    throw new Error("Cant load key from " + keyinfo);
};

var Box  = function Box (opts) {
    opts = opts || {};

    this.pubIdx = {};

    if (opts.keys) {
        opts.keys.map(load.bind(null, this.add.bind(this), opts.algo));
    }

    this._keys();
    this.algo = opts.algo || {};
};

Box.prototype._keys = function () {
    var certs = {};
    this.keys = Object.keys(this.pubIdx).map((function (idx) {
        var ret = this.pubIdx[idx];
        if (!ret.cert) {
            return ret;
        }

        var rdn = ret.cert.rdnSerial();
        certs[rdn] = ret.cert;
        return ret;
    }).bind(this));
    this.certs = certs;
};


Box.prototype.lookupCert = function (add, query) {
    var rdnQuery = Certificate.formatRDN(query.serialNumber, query.issuer.value);
    var idx;
    for (idx=0; idx < add.length; idx++) {
        if (add[idx] === undefined) {
            continue;
        }
        if (add[idx].rdnSerial() === rdnQuery) {
            return add[idx];
        }
    }
    if (query.issuer && query.issuer.type === 'rdn' && query.serialNumber) {
        rdnQuery = Certificate.formatRDN(query.serialNumber, query.issuer.value);
        if (this.certs[rdnQuery]) {
            return this.certs[rdnQuery];
        }
    }
    return add[0];
};


Box.prototype.add = function (keyinfo) {
    var pub;
    if (keyinfo.priv) {
        pub = keyinfo.priv.pub();
    }
    else if (keyinfo.cert) {
        pub = keyinfo.cert.pubkey;
    }
    else {
        return;
    }

    var idx = pub.point.toString();
    var container;

    if (this.pubIdx[idx] === undefined) {
        container = {};
        this.pubIdx[idx] = container;
    } else {
        container = this.pubIdx[idx];
    }

    container.priv = container.priv || keyinfo.priv;
    container.cert = container.cert || keyinfo.cert;
};

Box.prototype.load = function (keyinfo, algo) {
    load(this.add.bind(this), algo, keyinfo);
    this._keys();
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
        data = msg.as_transport(opts, cmd.addCert);
    }

    return data;
};

Box.prototype.unwrap = function (data, content) {
    var msg;
    var x;
    var info = {pipe: []};
    var tr;
    var signed;
    var key;
    var help_cert = [];
    while (data && data.length) {
        try {
            tr = transport.decode(data);
        } catch (e) {
            tr = null;
        }
        if (tr) {
            if (tr.header) {
                info.pipe.push({transport: true, headers: tr.header});
            }
            msg = tr.docs.shift();
            while(msg.type === 'CERTCRYPT') {
                help_cert.push(Certificate.from_asn1(msg.contents));
                msg = tr.docs.shift();
            }
            if (msg.type.substr(3) === '_CRYPT' || msg.type.substr(3) === '_SIGN') {
                data = msg.contents;
            }

            if (msg.type.substr(0, 3) === 'QLB' && tr.docs.length > 0) {
                content = tr.docs.shift().contents;
            }
            if (msg.type === 'DOCUMENT' && msg.encoding === 'PACKED_XML_DOCUMENT') {
                data = msg.contents;
                continue;
            }
        }
        try {
            msg = new Message(data);
        } catch (e) {
            if (tr === null) {
                break;
            }
            throw e;
        }
        if (msg.type === 'signedData') {
            if (msg.info.contentInfo.content === undefined) {
                if (content === undefined) {
                    info.pipe.push({error: "ENODATA"});
                    break;
                }
                msg.info.contentInfo.content = content;
            }
            signed = msg.verify(this.algo.hash);
            if (signed !== true) {
                info.pipe.push({broken_sign: true, error: "ESIGN"});
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
                signingTime: msg.pattrs.signingTime,
            });
        }
        if (msg.type === 'envelopedData') {
            key = this.keyFor('encrypt');
            if (key === undefined || key.priv === undefined) {
                info.pipe.push({ enc: true, error: "ENOKEY"});
                break;
            }
            info.pipe.push({
                enc: true,
            });
            try {
                data = msg.decrypt(
                        key.priv,
                        this.algo,
                        this.lookupCert.bind(this, help_cert)
                )
            } catch (e) {
                if (e instanceof Message.ENOCERT) {
                    info.pipe.push({ enc: true, error: "ENOCERT"});
                    break;
                }
                throw e;
            }
        }
    }
    info.content = data;
    if (info.pipe.length && info.pipe[info.pipe.length-1].error) {
        info.error = info.pipe[info.pipe.length-1].error;
    }
    return info;
};

module.exports = Box;
