'use strict';
var jksreader = require('jksreader'),
    Priv = require('../models/Priv'),
    Message = require('../models/Message'),
    Certificate = require('../models/Certificate'),
    transport = require('../util/transport'),
    pem = require('../util/pem.js'),
    fs = require('fs');

var loadJks = function loadJks (ret, store, password) {
    var idx, jidx;
    for(idx=0; idx < store.material.length; idx++) {
        var part = store.material[idx];
        var buf = jksreader.decode(part.key, password);
        if (!buf) {
            throw new Error("Cant load key from store");
        }
        var rawStore = Priv.from_asn1(buf, true);
        for(jidx=0; jidx < part.certs.length; jidx++) {
            ret({cert: Certificate.from_pem(part.certs[jidx])});
        }
        for(jidx=0; jidx < rawStore.keys.length; jidx++) {
            ret({priv: rawStore.keys[jidx]});
        }
    }
}

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
        var store = jksreader.parse(buf);
        var keys;
        if (store) {
            loadJks(ret, store, keyinfo.password);
            return;
        }
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

Box.prototype.sign = function sign (data, role, cert, opts) {
    var key = this.keyFor('sign', role);
    var msg = new Message({
        type: 'signedData',
        cert: key.cert,
        data: opts.detached ? null : data,
        dataHash: this.algo.hash(data),
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

var OP_TO_KEY_BIT = {
    sign: 0x80,
    encrypt: 0x08,
};
var filterUsage = function filterUsage(op, ob) {
    const data = ob.cert.extension.keyUsage;
    const bits = data[data.length - 1];
    return bits & OP_TO_KEY_BIT[op];
};

var DRFO_FORMAT = [
    /^[0-9]{10}$/, // standard DRFO code ten digits;
    /^[0-9]{9}$/, // id card (new passport) number nine digits used in lieu of DRFO code for religious people.
    /^[a-zA-Z]{2}[0-9]{6}$/, // old passport number AA123456 used in lieu of DRFO code for religious people.
];
function isNaturalPerson(code) {
    var idx;
    var format;
    for(idx=0; idx < DRFO_FORMAT.length; idx++) {
        format = DRFO_FORMAT[idx];
        if (code.match(format)) {
            return true;
        }
    }
    return false;
}

/* This code checks if certificate is suitable for given role.
 *
 * Possible values are:
 *
 * personal - certificate belongs to natural person and has no record
 *            of any corporate entity;
 * fop (fizychna osoba pidpryjemets) - certificate belongs to natural person
 *            registered as private entrepreneur, technically this means
 *            that personal code (10, 9 or 8 digit DRFO) matches corporate code (EDRPOU);
 * director - certificate either belongs to FOP or natural person that
 *            can sign on behalf of corporate entity, technicall this means
 *            that corporate code either matches drfo or drfo code is present,
 *            but corporate code does not belong to natural person;
 * stamp - certificate belongs to corporate entity itself, not natural person;
 * other - personal code is present but does not match corporate code (relaxed version of director);
 * exact personal code to match. should be 10, 9 or 8 characters long (see above)  */
var filterRole = function filerRole(role, ob) {
    var ipn = ob.cert.extension.ipn;
    if (!role) {
        return true;
    }
    if (role === 'personal') {
        return Boolean(!ipn.EDRPOU && ipn.DRFO);
    }
    if (role === 'fop') {
        return ipn.EDRPOU === ipn.DRFO;
    }
    if (role === 'director') {
        return ipn.EDRPOU === ipn.DRFO || (ipn.DRFO && !isNaturalPerson(ipn.EDRPOU));
    }
    if (role === 'stamp') {
        return Boolean(ipn.EDRPOU && !ipn.DRFO);
    }
    if (role === 'other') {
        return Boolean(ipn.DRFO && ipn.EDRPOU !== ipn.DRFO);
    }

    return ipn.DRFO === role;
}

Box.prototype.keyFor = function keyFor (op, role) {
    var keys = this.keys
        .filter(filterUsage.bind(null, op))
        .filter(filterRole.bind(null, role));
    if(!keys.length) {
        throw new Error("No key-certificate pair found for given op " + op + " and role " + role);
    }
    return keys[0];
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
        msg = this[cmd.op](data, cmd.role, cert, cmd);
        data = cmd.tax ? msg.as_transport(opts, cmd.addCert) : msg.as_asn1();
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
