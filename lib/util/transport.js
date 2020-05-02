const Buffer = require("buffer").Buffer;
const packed_xml = require("./packed_xml.js");
const b64_decode = require("./base64.js").b64_decode;
const invariant = require("./invariant.js").invariant;

// Regexp to find a pair of HTML tags.
// [\s\S] inside a tag matches all white-space characters + all non-whitespace
// characters, which gives us all characters including newline.
// The standard dot (.) does not match newline, and there is no 's' flag in JS
const regexp = new RegExp("<([\\w][\\w\\d]*)([^>]*)>([\\s\\S]*?)</\\1>", "g");

function U32(number) {
  const ret = Buffer.alloc(4);
  ret.writeUInt32LE(number);
  return ret;
}

function write_buf(buf, data) {
  invariant(data.length > 0, "Attempt to write empty buffer");
  invariant(Buffer.isBuffer(buf), "First argument should be buffer");
  invariant(
    Buffer.isBuffer(data) || typeof data === "string",
    "Second argument should be buffer or string"
  );

  return Buffer.concat([
    buf,
    typeof data === "string" ? Buffer.from(data, "binary") : data
  ]);
}

function transport_header(rb, headers) {
  rb = write_buf(rb, "TRANSPORTABLE\u0000");
  let h_buf = Buffer.alloc(0);
  Object.entries(headers).forEach(function([key, value]) {
    h_buf = write_buf(h_buf, key);
    h_buf = write_buf(h_buf, "=");
    h_buf = write_buf(h_buf, value);
    h_buf = write_buf(h_buf, "\r\n");
  });
  h_buf = write_buf(h_buf, "\u0000");
  rb = write_buf(rb, U32(h_buf.length));
  rb = write_buf(rb, h_buf);
  return rb;
}

function transport_encode(documents, headers) {
  let rb = Buffer.alloc(0);

  rb = headers ? transport_header(rb, headers) : rb;

  documents.forEach(function(el) {
    rb = write_buf(rb, el.type);
    rb = write_buf(rb, "\u0000");
    rb = write_buf(rb, U32(el.contents.length));
    rb = write_buf(rb, el.contents);
  });
  return rb;
}

var header_decode = function(buffer) {
  var ret = {};
  var key, val;
  var idx = 0;
  var st = idx;
  while (buffer[idx]) {
    if (buffer[idx] === 0x3d) {
      key = buffer.slice(st, idx).toString();
      st = idx + 1;
    }
    if (buffer[idx] === 0x0a && buffer[idx - 1] === 0x0d) {
      val = buffer.slice(st, idx - 1);
      ret[key] = val.toString("binary");
      st = idx + 1;
    }
    idx++;
  }
  return ret;
};

var qlb_split = function(buffer, print) {
  var off = 0;
  var ret = { data: [], hash: [] };
  var clen;
  var prev;

  while (off < buffer.length) {
    if (buffer[off] === 2) {
      off++;
      clen = buffer.readUInt32LE(off);
      off += 4;
      if (clen > 0) {
        ret.data.push(buffer.slice(off, off + clen));
        prev = "data";
      } else {
        prev = "zero";
      }
      off += clen;
    } else if (buffer[off] === 0x20) {
      off++;
      clen = 0x20;

      ret.hash.push(buffer.slice(off, off + clen));

      off += clen;
      prev = "hash";
    } else if (buffer.readUInt32BE(off) === 0) {
      off += 4;
      prev = "zero";
    } else if (prev !== undefined) {
      clen = buffer.readUInt32LE(off);
      off += 4;
      ret.data.push(buffer.slice(off, off + clen));

      off += clen;
      prev = "data";
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
    res.push({ name: partName, content: b64_decode(childElement[3]) });
  }

  return res;
};

var transport_decode = function(buffer) {
  var ret = { docs: [] };
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
          ret.docs.push({
            type: doc.name,
            contents: doc.content,
            encoding: "PACKED_XML_DOCUMENT"
          });
        } else {
          ret.header[doc.name] = doc.content;
        }
      }
      break;
    }

    while (buffer[off] && off - section < 20) {
      off++;
    }

    if (buffer[off] !== 0) {
      throw new Error("No label found");
    }

    label = buffer.slice(section, off).toString();
    if (label === "USC_SIGN" || label === "USC_CRYPT") {
      off++;
      section = off;
      continue;
    }
    clen = buffer[++off];
    clen |= buffer[++off] << 8;
    clen |= buffer[++off] << 16;
    clen |= buffer[++off] << 24;
    off++;
    if (clen < 0 || clen + off > buffer.length) {
      throw new Error("Invalid length of '" + label + "' section:" + clen);
    }

    if (label === "TRANSPORTABLE" || label === "ZPOSTTRANSPORTABLE") {
      ret.header = header_decode(buffer.slice(off, off + clen));
    } else if (label === "QLB_SIGN") {
      ct = qlb_split(buffer.slice(off, off + clen), off);
      ret.docs.push({ type: label, contents: ct.data[0], hash: ct.hash[0] });
      ret.docs.push({ type: "DATA", contents: ct.data[1] });
    } else if (label == "QLB_CRYPT") {
      ct = qlb_split(buffer.slice(off, off + clen), off);
      ret.docs.push({ type: "CERTCRYPT", contents: ct.data[0] });
      ret.docs.push({ type: label, contents: ct.data[1], hash: ct.hash[0] });
    } else {
      ret.docs.push({ type: label, contents: buffer.slice(off, off + clen) });
    }

    off += clen;
    section = off;
  }
  return ret;
};
module.exports = {
  encode: transport_encode,
  decode: transport_decode
};
