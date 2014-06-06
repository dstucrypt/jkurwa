var mul = require('./mul.js'),
    wnaf = require('./wnaf.js');

module.exports = {
    precomp: mul.precomp,
    mulPos: mul.mulPos,
    getWindowSize: wnaf.getWindowSize,
    windowNaf: wnaf.windowNaf,
    compactNaf: wnaf.compactNaf,
}
