"use strict";

/*
 * Decoder for MeDoc PACKED_XML containers.
 *
 * A PACKED_XML blob is LZMA-compressed XML wrapped by a small header and
 * lightly obfuscated (XOR) to deter naive inspection. unpack() reverses
 * the obfuscation (unobfuscate) and then LZMA-decompresses the result
 * (unlzma). Two obfuscation schemes exist: a legacy fixed-key XOR and a
 * newer "versioned" scheme detected by a trailer signature (getVersion).
 */
import lzmaDecoder from "js-lzma";
import { Buffer } from "buffer";

// Minimal byte-oriented input/output streams the js-lzma decoder expects.
var Stream = {
  inStream: function (data) {
    this.offset = 0;
    this.data = data;
    this.readByte = function () {
      return this.data[this.offset++];
    };
    this.readUInt32LE = function () {
      var res = this.data.readUInt32LE(this.offset);
      this.offset += 4;
      return res;
    };
    return this;
  },
  outStream: function (size) {
    this.offset = 0;
    this.data = Buffer.alloc(size);
    this.writeByte = function (value) {
      this.data[this.offset++] = value;
    };
    return this;
  }
};

// xor key for the legacy (pre-versioned) PACKED_XML obfuscation
var xorStr = [
  0x0e8, 0x0d5, 1, 3, 0x0c3, 0x0c1, 0x83, 0x3d, 0x0b7, 0x0f0, 0x41, 5, 7, 0x72,
  0x10, 0x0e8
];

/**
 * Detect whether data uses the newer versioned obfuscation and extract its params.
 * @param {Buffer} data - data past the 15-byte outer header.
 * @param {number} dataLen - length of that data.
 * @returns {{newFormat:boolean,nVer:number,bRand:number}} format flag, version, and random key byte.
 */
function getVersion(data, dataLen) {
  // ASCII "1234567890": the signature the trailer XORs must reproduce.
  var bytes = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30];

  var res = { newFormat: false, nVer: -1, bRand: 0 };

  if (dataLen < 77) {
    return res;
  }

  // the magic happens here...
  // Two 10-byte trailer regions XOR to the "1234567890" marker iff new format.
  for (var count = 0; count < 10; count++) {
    if (
      (data[dataLen - 13 + count] ^ data[dataLen - 23 + count]) !==
      bytes[count]
    ) {
      return res;
    }
  }

  res.newFormat = true;
  // bRand is a per-file random XOR byte; nVer is recovered by XOR of two bytes.
  res.bRand = data[dataLen - 3];
  res.nVer = data[dataLen - 2] ^ data[dataLen - 25];

  return res;
}

/**
 * Reverse the PACKED_XML XOR obfuscation and strip the header, yielding LZMA bytes.
 * @param {Buffer} packedXmlData - the full PACKED_XML blob (mutated in place).
 * @returns {Buffer} the raw LZMA stream (header removed).
 */
function unobfuscate(packedXmlData) {
  var dataLen, unpackedSize, fileInfo;

  dataLen = packedXmlData.length;

  // check header
  if (packedXmlData.slice(0, 10).toString() !== "PACKED_XML") {
    throw Error("This is not PACKED_XML");
  }

  // get unpacked data size
  unpackedSize = packedXmlData.readUInt32LE(11);

  // get lzma obfuscation version
  fileInfo = getVersion(packedXmlData.slice(15), dataLen - 15);
  if (fileInfo.newFormat) {
    if (fileInfo.nVer === 1) {
      // fixing header
      // New format v1: de-XOR the leading bytes against a tail region keyed
      // by the per-file random byte. Region size capped at 512 bytes.
      var count1 = dataLen - 28 > 1024 ? 512 : (dataLen - 28) / 2;
      for (var count = 0; count < count1; count++) {
        packedXmlData[15 + count] ^=
          packedXmlData[15 + dataLen - 28 - count1 + count] ^ fileInfo.bRand;
      }
    } else {
      throw Error("Unsupported PACKED_XML version: " + fileInfo.nVer);
    }
  } else {
    // xor first 160 bytes after header
    // Legacy format: XOR up to 160 bytes with the fixed 16-byte repeating key.
    dataLen - 15 > 160 ? (count1 = 160) : (count1 = dataLen - 15);
    for (var count = 0; count < count1; count++) {
      packedXmlData[15 + count] ^= xorStr[count % 16];
    }
  }

  // cut header
  return packedXmlData.slice(16);
}

/**
 * LZMA-decompress a raw LZMA stream.
 * @param {Buffer} lzmaData - the LZMA stream (props + size + data).
 * @returns {Buffer} the decompressed bytes.
 */
function unlzma(lzmaData) {
  var decoder, outSize, inStream, outStream;

  // construct input stream for LZMA decoder
  inStream = new Stream.inStream(lzmaData);

  // construct decoder and set properties from stream
  var decoder = new lzmaDecoder.Decoder();
  if (!decoder.setDecoderProperties(inStream)) {
    throw Error("Incorrect LZMA stream properties");
  }

  // data size from LZMA header
  outSize = inStream.readUInt32LE();

  // construct output stream and reserve space
  outStream = new Stream.outStream(outSize);

  // skip 4 zeroes...
  inStream.readUInt32LE();

  // actually decode
  if (!decoder.decode(inStream, outStream, outSize)) {
    throw Error("Error in LZMA data stream");
  }

  return outStream.data;
}

/**
 * Unpack a PACKED_XML blob: de-obfuscate then LZMA-decompress.
 * @param {Buffer} data - the full PACKED_XML blob.
 * @returns {Buffer} the decompressed XML content.
 */
function unpack(data) {
  // try to unobfuscate LZMA data
  var lzmaData = unobfuscate(data);
  if (lzmaData === undefined) {
    throw Error("Error unobfuscating data");
  }

  // now decompress them and return result
  return unlzma(lzmaData);
}

export { unpack };
