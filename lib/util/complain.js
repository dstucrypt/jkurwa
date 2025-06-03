class EOLD extends Error {}

function complain(msg) {
  if (!EOLD.silent) {
    console.error(msg, new EOLD());
  }
}

export default complain;
export { EOLD };