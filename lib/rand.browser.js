module.exports = function (fill) {
    return (window.crypto || window.msCrypto).getRandomValues(fill);
}
