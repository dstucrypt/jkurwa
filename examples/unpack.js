var jk = require('../lib/index');

var gost89 = require('gost89');
var fs = require('fs');


function main() {
    var contents = fs.readFileSync('Key-6.dat');
    var store = jk.models.Priv.from_protected(contents, 'PASSWORD', gost89.compat.algos());
    store.keys.map(function (key) {
      console.log(key.as_pem());
    });
};

main();
