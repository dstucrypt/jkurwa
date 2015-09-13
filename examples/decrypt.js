var fs = require('fs'),
    jk = require('../lib/index.js'),
    em_gost = require('em-gost'),
    keycoder = new jk.Keycoder();



var decrypt_buffer = function(u8, priv, cert) {
    var msg_wrap, msg, kek, cek, wcek, data;
    try {
        data = new Buffer(u8, 'binary');
        msg_wrap = new jk.models.Message(data);
    } catch(e) {
        console.log('e', e);
        throw new Error("Can't read file format");
    }

    if(msg_wrap.type === 'signedData') {
        msg = msg_wrap.unpack();
    } else {
        msg = msg_wrap;
    }

    try {
        cert = msg.signer();
    } catch(e) {
        try {
            cert = msg_wrap.signer();
        } catch(_ignore) {
            if(cert === undefined) {
                throw new Error("Cant find signer certifiate");
            }
        }
    }

    if(msg.type !== 'envelopedData') {
        console.log(msg.toString());
        throw new Error("File is not encrypted");
    }

    // assume only one recipient. can be not so
    kek = priv.sharedKey(cert.pubkey, msg.rki.ukm, em_gost.gost_kdf);
    wcek = msg.rki.recipientEncryptedKeys[0].encryptedKey;

    try {
        cek = em_gost.gost_unwrap(kek, wcek);
    } catch (e) {
        throw new Error("wailed to decrypt cek. key mismatch?");
    }
    return em_gost.gost_decrypt_cfb(msg.enc_contents, cek, msg.enc_params.iv);
};

function main() {
    var edata_b = fs.readFileSync('./enveloped.dat'), // encrypted content
        store_b = fs.readFileSync('./keystore.dat'), // raw keystore
        cert_b = fs.readFileSync('./cert.der'), // cert and pubkey
                                                // of recipient
        cert = keycoder.parse(cert_b),
        store = keycoder.parse(keycoder.maybe_pem(store_b));

    var ret = decrypt_buffer(edata_b, store.keys[0], cert);
    fs.writeFileSync('./out.dat', ret);
};

main();
