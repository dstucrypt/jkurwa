module.exports = function (fill) {
    return (global.crypto || global.msCrypto).getRandomValues(fill);
}
