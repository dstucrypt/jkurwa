const DRFO_FORMAT = [
  /^[0-9]{10}$/, // standard DRFO code ten digits;
  /^[0-9]{9}$/, // id card (new passport) number nine digits used in lieu of DRFO code for religious people.
  /^[a-zA-Z]{2}[0-9]{6}$/ // old passport number AA123456 used in lieu of DRFO code for religious people.
];
function isNaturalPerson(code) {
  for (let format of DRFO_FORMAT) {
    if (code.match(format)) {
      return true;
    }
  }
  return false;
}

/* This code checks if certificate is suitable for given role.
 *
 * Possible values are:
 *
 * personal - certificate belongs to natural person and has no record
 *            of any corporate entity;
 * corporate - certificate belongs to company employee, director or government official,
 *            both DRFO and EDRPOU codes are present;
 * stamp - certificate belongs to a corporate entity itself, not natural person,
 *            EDRPOU is prsent, but personal number (DRFO) is not;
 * director - certificate either belongs to FOP or natural person that
 *            can sign on behalf of corporate entity, technicall this means
 *            that corporate code either matches drfo or drfo code is present,
 *            but corporate code does not belong to natural person;
 * fop (fizychna osoba pidpryjemets) - certificate belongs to natural person
 *            registered as private entrepreneur, technically this means
 *            that personal code (10, 9 or 8 digit DRFO) matches corporate code (EDRPOU);
 * other - personal code is present but does not match corporate code (relaxed version of director);
 * exact personal code to match. should be 10, 9 or 8 characters long (see above)  */
const filterRole = function filerRole(role, ob) {
  if (!ob.cert) {
    return false;
  }
  const { ipn } = ob.cert.extension;
  if (!role) {
    return true;
  }
  if (role === "personal") {
    return Boolean(!ipn.EDRPOU && ipn.DRFO);
  }
  if (role === "corporate") {
    return Boolean(ipn.EDRPOU && ipn.DRFO);
  }
  if (role === "fop") {
    return ipn.EDRPOU === ipn.DRFO;
  }
  if (role === "director") {
    return (
      ipn.EDRPOU === ipn.DRFO || (ipn.DRFO && ipn.EDRPOU && !isNaturalPerson(ipn.EDRPOU))
    );
  }
  if (role === "stamp") {
    return Boolean(ipn.EDRPOU && !ipn.DRFO);
  }
  if (role === "other") {
    return Boolean(ipn.DRFO && ipn.EDRPOU !== ipn.DRFO);
  }

  return ipn.DRFO === role;
};
module.exports = filterRole;
