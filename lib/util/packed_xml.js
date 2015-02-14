'use strict';

var lzmaDecoder = require('js-lzma'),
    b64_decode = require('./base64.js').b64_decode;

var Stream = {
    inStream: function(data) {
        this.offset = 0;
        this.data = data;
        this.readByte = function() {
            return this.data[this.offset++];
        };
        this.readUInt32LE = function() {
            var res = this.data.readUInt32LE(this.offset);
            this.offset += 4;
            return res;
        }
        return this;
    },
    outStream: function(size) {
        this.offset = 0;
        this.data = new Buffer(size);
        this.writeByte = function(value) {
            this.data[this.offset++] = value;
        };
        return this;
    }
};

var Unpacker = function() {

    this.getVersion = function(data, dataLen) {

        var bytes = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30];
        var xorStr = [0x0E8, 0x0D5, 1, 3, 0x0C3, 0x0C1, 0x83, 0x3D, 0x0B7, 0x0F0, 0x41, 5, 7, 0x72, 0x10, 0x0E8];

        var res = {'newFormat': false, 'nVer': -1, bRand: 0};

        if (dataLen < 77) {
            return res;
        }

        // the magic happens here...
        for (var count = 0; count < 10; count++) {
            if (((data[dataLen - 13 + count]) ^ (data[dataLen - 23 + count])) !== bytes[count]) {
                return res;
            }
        }

        res.newFormat = true;
        res.bRand = data[dataLen - 3];
        res.nVer = data[dataLen - 2] ^ data[dataLen - 25];

        return res;

    };

    this.unobfuscate = function(packedXmlData) {

        var dataLen, unpackedSize, fileInfo;

        dataLen = packedXmlData.length;

        // check header
        if (packedXmlData.slice(0, 10).toString() !== "PACKED_XML") {
            throw "This is not PACKED_XML";
        }

        // get unpacked data size
        unpackedSize = packedXmlData.readUInt32LE(11);

        // get lzma obfuscation version
        fileInfo = this.getVersion(packedXmlData.slice(15), dataLen - 15);
        if (fileInfo.newFormat) {
            if (fileInfo.nVer === 1) {
                // fixing header
                var count1 = (dataLen - 28) > 1024 ? 512 : (dataLen - 28) / 2;
                for (var count = 0; count < count1; count++) {
                    packedXmlData[15 + count] ^= packedXmlData[15 + dataLen - 28 - count1 + count] ^ fileInfo.bRand;
                }
            } else {
                throw "Unsupported PACKED_XML version: " + fileInfo.nVer;
            }
        } else {
            // xor first 160 bytes after header
            dataLen - 15 > 160 ? count1 = 160 : count1 = dataLen - 15;
            for (var count = 0; count < count1; count++) {
                packedXmlData[15 + count] ^= xorStr[count % 16];
            }
        }

        // cut header
        return packedXmlData.slice(16);

    };

    this.unlzma = function(data) {

        var lzmaData, decoder, outSize, inStream, outStream;

        // try to unobfuscate LZMA data
        lzmaData = this.unobfuscate(data);
        if (lzmaData === undefined) {
            throw "Error unobfuscating data";
        }

        // construct input stream for LZMA decoder
        inStream = new Stream.inStream(lzmaData);

        // construct decoder and set properties from stream
        var decoder = new lzmaDecoder.Decoder();
        if (!decoder.setDecoderProperties(inStream)) {
            throw "Incorrect LZMA stream properties";
        }

        // data size from LZMA header
        outSize = inStream.readUInt32LE();

        // construct output stream and reserve space
        outStream = new Stream.outStream(outSize);

        // skip 4 zeroes...
        inStream.readUInt32LE();

        // actually decode
        if (!decoder.decode(inStream, outStream, outSize)) {
            throw "Error in LZMA data stream";
        };

        return outStream.data;
    };

    this.unpack = function(data) {

        var xmlBuf, xml, el, partName;
        var res = {};
        // Regexp to find a pair of HTML tags.
        // [\s\S] inside a tag matches all white-space characters + all non-whitespace
        // characters, which gives us all characters including newline.
        // The standard dot (.) does not match newline, and there is no 's' flag in JS
        var regexp = new RegExp('<([\\w][\\w\\d]*)([^>]*)>([\\s\\S]*?)</\\1>', 'g');
        var rootElement, childElement;

        xmlBuf = this.unlzma(data);

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
            res[partName] = b64_decode(childElement[3]);
        }

        return res;

    }

    return this;

};

var newUnpacker = function() {
    return new Unpacker();
}

module.exports.Unpacker = newUnpacker;
