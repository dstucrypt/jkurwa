var write_buf = function(buf, data) {
    if(!data.length) {
        throw new Error("Can't write data of unknown length");
    }

    if(buf._pos === undefined) {
        buf._pos = 0;
    }
    var wlen;
    if(Buffer.isBuffer(data)) {
        wlen = data.copy(buf, buf._pos);
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

module.exports = {
    encode: transport_encode,
};
