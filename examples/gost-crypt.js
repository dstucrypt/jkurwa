var jk = require('../lib/index.js'),
    gost89 = require('gost89');

/*
   Data encryption with DSTU 4145 and GOST block cipher.
   See gost-decrypt.js to decrypt this message.

   keys:

   reciever:
     priv: 171b130e180d060f1f1a0807011816170f060b040a10121817111a0d0b0b0f03
     pub:  e54bf3f92a281d02f46ad5637387a8f13c9698816cb4f8beadfc0565fa63d6b1

   sender:
     priv: 40a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d
     pub:  40ad1cb010531b504177577d8d4ad148219eb0c9bda61c9a0d4df1650d8cbe22

*/

// text we need to sign
text = new Buffer("{'msg': 'hello', 'code': 1}");

// agreed keys
sender_priv = jk.pkey('DSTU_PB_257', '40a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d');
reciever_pub = jk.pubkey('DSTU_PB_257', 'e54bf3f92a281d02f46ad5637387a8f13c9698816cb4f8beadfc0565fa63d6b1');

// random values choosen by sender
//  ukm (salt, 64 bytes), iv (cipher param, 8 bytes), cek - 32 bytes key 

ukm = new Buffer('0a151914091304101b1a140f1c1d0b1d091c121f07091e0d1a0118011b02171a0f0b001c14011401121a0e1b090305021b190b081c02121a1f1d0a04080b1418', 'hex');
iv = new Buffer('09100509181c0515', 'hex');
cek = new Buffer('11080811020a0d0913040f020111190b04060c101d1c0a0911060e160b121419', 'hex');

// compute sharedkey and wrap encryption key
sharedkey = sender_priv.sharedKey(reciever_pub, ukm, gost89.gosthash);
wcek = gost89.wrap_key(cek, sharedkey, iv);

// finally encrypt text
ciphered = gost89.compat.gost_encrypt_cfb(text, cek, iv);

console.log("sender should transmit following infomration to reciever: ");
console.log("    wrapped key    : " + wcek.toString("hex"));
console.log("    ukm            : " + ukm.toString("hex"));
console.log("    iv             : " + iv.toString("hex"));
console.log("    encrypted text : " + ciphered.toString("hex"));
