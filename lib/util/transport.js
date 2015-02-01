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

var transport_decode = function (buffer) {
    var ret = {docs: []};
    var off = 0;
    var section = 0;
    var label;
    var clen;

    while (off < buffer.length) {

        while (buffer[off] && (off - section) < 20) {
            off ++;
        }

        if (buffer[off] !== 0) {
            throw new Error("No label found");
        }

        label = buffer.slice(section, off).toString();
        if (label === 'USC_SIGN') {
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

        if (label === 'TRANSPORTABLE') {
            ret.header = header_decode(buffer.slice(off, off + clen));
        } else if (label.substr(0, 3) === 'QLB') {
            off += 46;
            clen = buffer.readUInt32LE(off);
            off += 4;
            ret.docs.push({type: label, contents: buffer.slice(off, off + clen)});
            off += clen;
            clen = buffer.readUInt32LE(off);
            off += 4;
            ret.docs.push({type: 'DATA', contents: buffer.slice(off, off + clen)});
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
