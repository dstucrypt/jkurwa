var jk = require('../lib/index.js'),
    gost89 = require('gost89');

// keys used
reciever_priv = jk.pkey('DSTU_PB_257', '171b130e180d060f1f1a0807011816170f060b040a10121817111a0d0b0b0f03');
sender_pub = jk.pubkey('DSTU_PB_257', '40ad1cb010531b504177577d8d4ad148219eb0c9bda61c9a0d4df1650d8cbe22');

// recived message
// ukm (salt), iv (cipher param) and encrypted text
ukm = new Buffer('0a151914091304101b1a140f1c1d0b1d091c121f07091e0d1a0118011b02171a0f0b001c14011401121a0e1b090305021b190b081c02121a1f1d0a04080b1418', 'hex');
iv = new Buffer('09100509181c0515', 'hex');
wcek = new Buffer('359a37cf972520b590ef109b7c454c991d95da782e30ac9fe917fbb52e9402a4d236fd030f49627ec63c2684', 'hex');
ciphered = new Buffer('9fa6c038bf04e8810f7d3d25beb6fd9ee7efe0698e4f1216f17316', 'hex');

// generate shared secret and unwrap message key
sharedkey = reciever_priv.sharedKey(sender_pub, ukm, gost89.gosthash);
cek = gost89.unwrap_key(wcek, sharedkey, iv);

// finally decrypt message
text = gost89.compat.gost_decrypt_cfb(ciphered, cek, iv);

console.log("deciphered text " + text);
