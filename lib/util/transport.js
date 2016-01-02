var Buffer = require('buffer').Buffer;
var packed_xml = require('./packed_xml.js'),
    b64_decode = require('./base64.js').b64_decode;

// Regexp to find a pair of HTML tags.
// [\s\S] inside a tag matches all white-space characters + all non-whitespace
// characters, which gives us all characters including newline.
// The standard dot (.) does not match newline, and there is no 's' flag in JS
var regexp = new RegExp('<([\\w][\\w\\d]*)([^>]*)>([\\s\\S]*?)</\\1>', 'g');

var write_buf = function(buf, data) {
    if(!data.length) {
        throw new Error("Can't write data of unknown length");
    }

    if(buf._pos === undefined) {
        buf._pos = 0;
    }
    var wlen;
    if (Array.isArray(data)) {
        data = new Buffer(data);
    }
    if (Buffer.isBuffer(data)) {
        wlen = data.copy(buf, buf._pos);
        if (wlen === undefined) {
            wlen = Math.min(buf.length - buf._pos, data.length);
        }
    } else {
        wlen = buf.write(data, buf._pos);
    }
    if(wlen === data.length) {
        buf._pos += wlen;
        return buf;
    }

    var nb;
    if(wlen < data.length) {
        nb = new Buffer(Math.max(buf.length * 2, data.length * 2));
        nb._pos = buf._pos;
        buf.copy(nb);
        buf = nb;
    } else {
        throw new Error("Impossible happened");
    }

    if(Buffer.isBuffer(data)) {
        wlen = data.copy(buf, buf._pos);
        if (wlen === undefined) {
            wlen = Math.min(buf.length - buf._pos, data.length);
        }
    } else {
        wlen = buf.write(data, buf._pos);
    }

    if(wlen !== data.length) {
        throw new Error("Failed to grow buffer");
    }

    buf._pos += wlen;
    return buf;
};

var transport_header = function(rb, headers) {
    var len_pos;
    rb = write_buf(rb, "TRANSPORTABLE\u0000");
    len_pos = rb._pos;
    rb._pos += 4;
    Object.keys(headers).map(function(el) {
        rb = write_buf(rb, el);
        rb = write_buf(rb, '=');
        rb = write_buf(rb, headers[el]);
        rb = write_buf(rb, '\r\n');
    });
    rb = write_buf(rb, '\u0000');
    rb.writeUInt32LE(rb._pos - len_pos - 4, len_pos);
    return rb;
};

var transport_encode = function(documents, headers) {
    var rb = new Buffer(1024);

    if(headers) {
        rb = transport_header(rb, headers);
    }

    documents.map(function(el) {
        rb = write_buf(rb, el.type);
        rb = write_buf(rb,'\u0000');
        rb.writeUInt32LE(el.contents.length, rb._pos);
        rb._pos += 4;
        rb = write_buf(rb, el.contents);
    });
    return rb.slice(0, rb._pos);
};

var header_decode = function (buffer) {
    var ret = {};
    var key, val;
    var idx = 0;
    var st = idx;
    while (buffer[idx]) {
        if (buffer[idx] === 0x3D) {
            key = buffer.slice(st, idx).toString();
            st = idx + 1;
        }
        if (buffer[idx] === 0x0A && buffer[idx-1] === 0x0D) {
            val = buffer.slice(st, idx - 1);
            ret[key] = val.toString('binary');
            st = idx + 1;
        }
        idx++;
    }
    return ret;
};


var qlb_split = function (buffer, print) {
    var off = 0;
    var ret = {data: [], hash: []};
    var clen;
    var prev;

    while (off < buffer.length) {
        if (buffer[off] === 2) {
            off++;
            clen = buffer.readUInt32LE(off);
            off += 4;
            if (clen > 0) {
                ret.data.push(buffer.slice(off, off + clen));
                prev = 'data';
            } else {
                prev = 'zero';
            }
            off += clen;
        } else if (buffer[off] === 0x20) {
            off ++;
            clen = 0x20;

            ret.hash.push(buffer.slice(off, off + clen));

            off += clen;
            prev = 'hash'
        } else if (buffer.readUInt32BE(off) === 0) {
            off += 4;
            prev = 'zero';
        } else if (prev !== undefined) {
            clen = buffer.readUInt32LE(off);
            off += 4;
            ret.data.push(buffer.slice(off, off + clen));

            off += clen;
            prev = 'data';
        } else {
            throw new Error("Unable to split QLB");
        }
    }

    return ret;
};

var decode_packed_xml_contents = function(xmlBuf) {
    var el, partName;
    var res = [];
    var rootElement, childElement;

    if (xmlBuf.slice(0, 5).toString() !== "<?xml") {
        throw Error("This is not XML");
    }

    // first find root tag
    rootElement = regexp.exec(xmlBuf.toString());
    if (rootElement === null) {
        throw Error("Invalid XML data - cannot find root element");
    }
    if (rootElement.length < 4) {
        throw Error("Invalid XML data - cannot process root element");
    }

    // now go through it's elements
    regexp.lastIndex = 0;
    while ((childElement = regexp.exec(rootElement[3])) !== null) {
        if (childElement.length < 4) {
            continue;
        }
        partName = childElement[1] + childElement[2];
        res.push({name: partName, content: b64_decode(childElement[3])});
    }

    return res;
}

var transport_decode = function (buffer) {
    var ret = {docs: []};
    var off = 0;
    var section = 0;
    var label;
    var clen;
    var ct;

    while (off < buffer.length) {

        if (buffer.slice(0, 10).toString() === "PACKED_XML") {
            try {
                ct = packed_xml.unpack(buffer);
                ct = decode_packed_xml_contents(ct);
            } catch (e) {
                // let the user know that something wrong,
                // as exception will be eaten later...
                console.error(e.message);
                throw e;
            }
            ret.header = {};
            while (ct.length > 0) {
                var doc = ct.shift();
                if (doc.name === "DOCUMENT") {
                    ret.docs.push({type: doc.name, contents: doc.content, encoding: "PACKED_XML_DOCUMENT"});
                } else {
                    ret.header[doc.name] = doc.content;
                }
            }
            break;
        }

        while (buffer[off] && (off - section) < 20) {
            off ++;
        }

        if (buffer[off] !== 0) {
            throw new Error("No label found");
        }

        label = buffer.slice(section, off).toString();
        if (label === 'USC_SIGN' || label === 'USC_CRYPT') {
            off++;
            section = off;
            continue;
        }
        clen = buffer[++off];
        clen |= (buffer[++off] << 8);
        clen |= (buffer[++off] << 16);
        clen |= (buffer[++off] << 24);
        off++;
        if (clen < 0 || (clen + off) > buffer.length) {
            throw new Error("Invalid length of '" + label + "' section:" + clen);
        }

        if (label === 'TRANSPORTABLE' || label === 'ZPOSTTRANSPORTABLE') {
            ret.header = header_decode(buffer.slice(off, off + clen));
        } else if (label === 'QLB_SIGN') {
            ct = qlb_split(buffer.slice(off, off + clen), off);
            ret.docs.push({type: label, contents: ct.data[0], hash: ct.hash[0]});
            ret.docs.push({type: 'DATA', contents: ct.data[1]});
        } else if (label == 'QLB_CRYPT') {
            ct = qlb_split(buffer.slice(off, off + clen), off);
            ret.docs.push({type: 'CERTCRYPT', contents: ct.data[0]});
            ret.docs.push({type: label, contents: ct.data[1], hash: ct.hash[0]});
        } else {
            ret.docs.push({type: label, contents: buffer.slice(off, off + clen)});
        }

        off += clen;
        section = off;
    }
    return ret;
};
module.exports = {
    encode: transport_encode,
    decode: transport_decode,
};
