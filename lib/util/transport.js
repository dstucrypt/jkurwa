/*
 * Encoder/decoder for the Ukrainian tax-office transport envelope.
 *
 * The envelope is a flat sequence of NUL-terminated ASCII labels, each
 * followed by a little-endian uint32 length and that many content bytes.
 * Known labels include TRANSPORTABLE / ZPOSTTRANSPORTABLE (a headers
 * block), USC_SIGN / USC_CRYPT (skippable markers), QLB_SIGN / QLB_CRYPT
 * (documents packaged with hashes), and PACKED_XML (an LZMA-compressed
 * XML container decoded via packed_xml). encode() builds such envelopes;
 * decode() parses them back into headers and documents.
 */
import { Buffer } from "buffer";
import * as packed_xml from "./packed_xml.js";
import { b64_decode } from "./base64.js";
import { invariant } from "./invariant.js";

// Regexp to find a pair of HTML tags.
// [\s\S] inside a tag matches all white-space characters + all non-whitespace
// characters, which gives us all characters including newline.
// The standard dot (.) does not match newline, and there is no 's' flag in JS
const regexp = new RegExp("<([\\w][\\w\\d]*)([^>]*)>([\\s\\S]*?)</\\1>", "g");

/**
 * Encode a number as a 4-byte little-endian buffer (the envelope's length prefix format).
 * @param {number} number - unsigned 32-bit value.
 * @returns {Buffer} 4-byte LE buffer.
 */
function U32(number) {
  const ret = Buffer.alloc(4);
  ret.writeUInt32LE(number);
  return ret;
}

/**
 * Append data to a buffer, coercing strings via binary (latin1) encoding.
 * @param {Buffer} buf - accumulator buffer.
 * @param {Buffer|string} data - bytes or string to append (must be non-empty).
 * @returns {Buffer} new concatenated buffer.
 */
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

/**
 * Write the TRANSPORTABLE header section (key=value\r\n lines) into the envelope.
 * @param {Buffer} rb - envelope buffer built so far.
 * @param {Object.<string,string>} headers - header key/value pairs.
 * @returns {Buffer} envelope with the header section appended.
 */
// Label is NUL-terminated, then a uint32 length prefix, then the header block.
// Each header line is "key=value" terminated by CRLF; a trailing NUL closes it.
function transport_header(rb, headers) {
  rb = write_buf(rb, "TRANSPORTABLE\u0000");
  let h_buf = Buffer.alloc(0);
  Object.entries(headers).forEach(function ([key, value]) {
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

/**
 * Encode documents (and optional headers) into a transport envelope buffer.
 * @param {Array.<{type:string,contents:Buffer}>} documents - document sections to emit.
 * @param {Object.<string,string>} [headers] - optional TRANSPORTABLE headers.
 * @returns {Buffer} the assembled envelope.
 */
function transport_encode(documents, headers) {
  let rb = Buffer.alloc(0);

  rb = headers ? transport_header(rb, headers) : rb;

  // Each document: NUL-terminated type label, uint32 length, then contents.
  documents.forEach(function (el) {
    rb = write_buf(rb, el.type);
    rb = write_buf(rb, "\u0000");
    rb = write_buf(rb, U32(el.contents.length));
    rb = write_buf(rb, el.contents);
  });
  return rb;
}

/**
 * Parse a "key=value\r\n" header block into an object.
 * @param {Buffer} buffer - the raw header block (parsed until a NUL byte).
 * @returns {Object.<string,string>} decoded headers.
 */
var header_decode = function (buffer) {
  var ret = {};
  var key, val;
  var idx = 0;
  var st = idx;
  // Scan until the terminating NUL byte (loop ends when buffer[idx] === 0).
  while (buffer[idx]) {
    // 0x3d '=' separates key from value; capture the key seen so far.
    if (buffer[idx] === 0x3d) {
      key = buffer.slice(st, idx).toString();
      st = idx + 1;
    }
    // 0x0d 0x0a (CRLF) terminates a value; store it as latin1/binary.
    if (buffer[idx] === 0x0a && buffer[idx - 1] === 0x0d) {
      val = buffer.slice(st, idx - 1);
      ret[key] = val.toString("binary");
      st = idx + 1;
    }
    idx++;
  }
  return ret;
};

/**
 * Split a QLB_SIGN/QLB_CRYPT section into its data chunks and 32-byte hashes.
 * @param {Buffer} buffer - the QLB section body.
 * @param {number} [print] - unused offset (kept for signature compatibility).
 * @returns {{data:Buffer[],hash:Buffer[]}} extracted data chunks and hashes.
 */
var qlb_split = function (buffer, print) {
  var off = 0;
  var ret = { data: [], hash: [] };
  var clen;
  var prev;

  while (off < buffer.length) {
    // Tag 0x02: a data chunk prefixed with a uint32 LE length.
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
      // Tag 0x20: a fixed 32-byte (0x20) hash follows.
      off++;
      clen = 0x20;

      ret.hash.push(buffer.slice(off, off + clen));

      off += clen;
      prev = "hash";
    } else if (buffer.readUInt32BE(off) === 0) {
      // Four zero bytes: padding/separator, skip.
      off += 4;
      prev = "zero";
    } else if (prev !== undefined) {
      // Untagged trailing chunk: read as a uint32 LE length-prefixed blob.
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

/**
 * Extract the base64-decoded child parts from an unpacked PACKED_XML document.
 * @param {Buffer} xmlBuf - the decompressed XML buffer.
 * @returns {Array.<{name:string,content:Buffer}>} named, base64-decoded parts.
 */
var decode_packed_xml_contents = function (xmlBuf) {
  var partName;
  var res = [];
  var rootElement, childElement;

  // PACKED_XML always begins with the XML prolog "<?xml".
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
    // Part name = tag name + its raw attributes; body is base64-encoded.
    partName = childElement[1] + childElement[2];
    res.push({ name: partName, content: b64_decode(childElement[3]) });
  }

  return res;
};

/**
 * Decode a transport envelope into its headers and document sections.
 * @param {Buffer} buffer - the raw envelope bytes.
 * @returns {{docs:Array,header?:Object}} parsed documents and headers.
 */
var transport_decode = function (buffer) {
  var ret = { docs: [] };
  var off = 0;
  var section = 0;
  var label;
  var clen;
  var ct;

  while (off < buffer.length) {
    // Whole payload is a single PACKED_XML container: unpack + parse it.
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

    // Advance to the NUL that terminates the label (labels are < 20 bytes).
    while (buffer[off] && off - section < 20) {
      off++;
    }

    if (buffer[off] !== 0) {
      throw new Error("No label found");
    }

    label = buffer.slice(section, off).toString();
    // USC_SIGN/USC_CRYPT are bare markers with no length/body; skip past NUL.
    if (label === "USC_SIGN" || label === "USC_CRYPT") {
      off++;
      section = off;
      continue;
    }
    // Read the little-endian uint32 length that follows the label's NUL.
    clen = buffer[++off];
    clen |= buffer[++off] << 8;
    clen |= buffer[++off] << 16;
    clen |= buffer[++off] << 24;
    off++;
    if (clen < 0 || clen + off > buffer.length) {
      throw new Error("Invalid length of '" + label + "' section:" + clen);
    }

    if (label === "TRANSPORTABLE" || label === "ZPOSTTRANSPORTABLE") {
      // Header block: key=value lines.
      ret.header = header_decode(buffer.slice(off, off + clen));
    } else if (label === "QLB_SIGN") {
      // Signed package: data[0] is the signature doc, data[1] the payload.
      ct = qlb_split(buffer.slice(off, off + clen), off);
      ret.docs.push({ type: label, contents: ct.data[0], hash: ct.hash[0] });
      ret.docs.push({ type: "DATA", contents: ct.data[1] });
    } else if (label == "QLB_CRYPT") {
      // Encrypted package: data[0] is the recipient cert, data[1] the ciphertext.
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

export default {
  encode: transport_encode,
  decode: transport_decode
};
