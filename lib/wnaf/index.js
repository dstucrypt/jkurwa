var mul = require('./mul'),
    wnaf = require('./wnaf');

module.exports = {
    precomp: mul.precomp,
    mulPos: mul.mulPos,
    getWindowSize: wnaf.getWindowSize,
    windowNaf: wnaf.windowNaf,
    compactNaf: wnaf.compactNaf,
}
