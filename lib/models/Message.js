'use strict';

var dstszi2010 = require('../spec/dstszi2010.js'),
    ContentInfo = dstszi2010.ContentInfo,
    Certificate = require('./certificate.js');

/*
    Need spec for this. This is something like key=value document
    with magic header, key-value pairs and body
*/
var prefixed_with = function (buffer, prefix, idx) {
    idx = idx || 0;
    var sliced = buffer.slice(idx, idx + prefix.length);

    return sliced.toString() === prefix;
}
var decode_transport = function (buffer, wait_label) {
    var i=0, skip = 2, sliced;
    if(wait_label) {
        for(i=0; i<buffer.length; i++) {
            if(prefixed_with(buffer, wait_label, i)) {
                break;
            }
        };
    }
    for(; i<buffer.length; i++) {
        if(skip) {
            if(buffer[i] === 0) {
                skip -= 1;
            }
        } else {
            if(buffer[i] !== 0)
                break;
        }
    }
    return {
        type: "taxTransport",
        contents: buffer.slice(i),
    }
}

var Message = function(asn1_ob) {
    var ob;

    var parse = function(data) {
        if(prefixed_with(data, 'TRANSPORTABLE\0')) {
            data = decode_transport(data, 'UA1_SIGN\0').contents;
        }
        var s_content_info = ContentInfo.decode(data, 'der');
        var s_model = ContentInfo.contentModel[s_content_info.contentType];
        var s_content = s_model.decode(s_content_info.content.value, 'der');

        ob.type = s_content_info.contentType;
        ob.info = s_content;

        if(ob.type == 'envelopedData') {
            // extract encryption params from asn1
            ob.enc_info = ob.info.encryptedContentInfo;
            ob.enc_params = ob.enc_info.contentEncryptionAlgorithm.parameters.value;
            if(ob.info.recipientInfos.length == 1) {
                ob.rki = ob.info.recipientInfos[0].value;
            }
            ob.enc_contents = ob.info.encryptedContentInfo.encryptedContent;
        }
    }

    var unpack = function() {
        if(ob.type == 'signedData') {
            var buffer = ob.info.contentInfo.content.value,
                data;

            if(prefixed_with(buffer, 'UA1_CRYPT\0')) {
                data = decode_transport(buffer);
                if( (data.contents[0] == 0x30) && (data.contents[1] & 0x80)) {
                    try {
                        return new Message(data.contents);
                    } catch(e) { }
                }
                return data;
            }
            return buffer;
        }
        if(ob.type === 'envelopedData') {
            return ob.enc_contents;
        }
    };

    var signer = function() {
        return new Certificate(ob.info.certificate);
    };

    ob = {
        parse: parse,
        type: null,
        info: null,
        unpack: unpack,
        signer: signer,
    };

    ob.parse(asn1_ob);

    return ob;
}

module.exports =  Message;
