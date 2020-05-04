const fs = require("fs");
const jk = require("../lib/index.js");
const gost89 = require("gost89");

function decrypt_buffer(u8, priv, cert) {
  let msg_wrap, msg, data;
  try {
    data = Buffer.from(u8, "binary");
    msg_wrap = new jk.models.Message(data);
  } catch (e) {
    console.log("e", e);
    throw new Error("Can't read file format");
  }

  if (msg_wrap.type === "signedData") {
    msg = new jk.models.Message(msg.info.contentInfo.content);
  } else {
    msg = msg_wrap;
  }
  return msg.decrypt(priv, gost89.compat.algos(), () => cert);
}

function main() {
  const edata_b = fs.readFileSync(`${__dirname}/../test/data/enc_message.p7`); // encrypted content
  const store_b = fs.readFileSync(`${__dirname}/../test/data/Key40A0.cer`); // private key of recepient
  const cert_b = fs.readFileSync(
    `${__dirname}/../test/data/SELF_SIGNED_ENC_6929.cer`
  ); // cert and pubkey of sender
  const cert = jk.Certificate.from_asn1(cert_b);
  const priv = jk.Priv.from_asn1(store_b);

  const ret = decrypt_buffer(edata_b, priv, cert);
  fs.writeFileSync("./out.dat", ret);
}

main();
