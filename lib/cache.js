var Big = require('../3rtparty/jsbn.packed.js');

var BASE_257 = '2a29ef207d0e9b6c55cd260b306c7e007ac491ca1b10c62334a9e8dcd8d20fb6';
var BASE_431 = ('1a62ba79d98133a16bbae7ed9a8e03c32e0824d57aef72f88986874e5aae49c' +
        '27bed49a2a95058068426c2171e99fd3b43c5947c857c');

var expand_cache = {};
expand_cache[BASE_257] = {
    x: new Big('2a29ef207d0e9b6c55cd260b306c7e007ac491ca1b10c62334a9' +
                'e8dcd8d20fb7', 16),
    y: new Big('10686d41ff744d4449fccf6d8eea03102e6812c93a9d60b978b7' +
                '02cf156d814ef', 16),
};

expand_cache[BASE_431] = {
    x: new Big('1a62ba79d98133a16bbae7ed9a8e03c32e0824d57aef72f88986874e5aae49c27' +
               'bed49a2a95058068426c2171e99fd3b43c5947c857d', 16),
    y: new Big('70b5e1e14031c1f70bbefe96bdde66f451754b4ca5f48da241f331aa396b8d183' +
               '9a855c1769b1ea14ba53308b5e2723724e090e02db9', 16),
};

module.exports = expand_cache;
