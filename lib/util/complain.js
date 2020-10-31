class EOLD extends Error {}

function complain(msg) {
  if (!EOLD.silent) {
    console.error(msg, new EOLD());
  }
}

module.exports = complain;
module.exports.EOLD = EOLD;
