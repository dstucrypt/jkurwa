'use strict';

var lzmaDecoder = require('js-lzma')

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

function getVersion(data, dataLen) {
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
            var count1 = (dataLen - 28) > 1024 ? 512 : (dataLen - 28) / 2;
            for (var count = 0; count < count1; count++) {
                packedXmlData[15 + count] ^= packedXmlData[15 + dataLen - 28 - count1 + count] ^ fileInfo.bRand;
            }
        } else {
            throw Error("Unsupported PACKED_XML version: " + fileInfo.nVer);
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
    };

    return outStream.data;
};

function unpack(data) {
    // try to unobfuscate LZMA data
    var lzmaData = unobfuscate(data);
    if (lzmaData === undefined) {
        throw Error("Error unobfuscating data");
    }

    // now decompress them and return result
    return unlzma(lzmaData);
}

module.exports.unpack = unpack;
