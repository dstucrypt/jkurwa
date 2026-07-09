jkurwa
======

[English](./README.md) · **Українська**

Українська національна криптографія (ДСТУ 4145) для JavaScript — еліптичні криві
над полем GF(2ᵐ), цифрові підписи, зашифровані контейнери та формати повідомлень
PKCS#7 / CMS, які використовують податкова служба та системи ПРРО.

Чистий JavaScript, працює в Node.js і в браузері.

[![npm module](https://badge.fury.io/js/jkurwa.svg)](https://www.npmjs.org/package/jkurwa)
[![test](https://github.com/dstucrypt/jkurwa/actions/workflows/test.yml/badge.svg)](https://github.com/dstucrypt/jkurwa/actions/workflows/test.yml)

![cej repo je strefa wolna wid Kaczyńskiego](https://raw.githubusercontent.com/muromec/jkurwa/master/kdpv.jpg)

Можливості
----------

* **Підписи ДСТУ 4145** — створення та перевірка підписів на коротких кривих
  Вейєрштрасса у двійковому полі GF(2ᵐ), зі стандартними іменованими кривими
  (напр. `DSTU_PB_257`) або власною кривою.
* **Хеш-функції** — ГОСТ 34.311-95 (через [gost89](https://github.com/dstucrypt/gost89))
  та **Купина / ДСТУ 7564:2014**; хеш обирається автоматично за сертифікатом
  підписанта або задається примусово. Див. [Хеш-функції](#хеш-функції).
* **Контейнери ключів** — читання та розшифрування `Key-6.dat` (пропрієтарний IIT),
  PBES2, PKCS#12 / PFX та JKS (використовує ПриватБанк).
* **Підписані та зашифровані повідомлення** — повне читання/запис «дикого» формату
  PKCS#7 / CMS, що використовує податкова (`sta.gov.ua`), разом із транспортним
  конвертом `TRANSPORTABLE`. Див. `jk.Box` та `jk.transport`.
* **Сертифікати та PKI** — парсери й побудова сертифікатів X.509 v3, а також
  запити й відповіді TSP (мітки часу), CMP та OCSP.
* **Шифрування** — узгодження ключів і загортання ключа блоковим шифром
  ГОСТ 28147 для зашифрованих контейнерів (за наявності реалізації шифру gost89).

Встановлення
------------

```sh
npm install jkurwa gost89
```

`gost89` надає блоковий шифр ГОСТ, загортання ключів і завантажувачі контейнерів
і передається як об'єкт `algo`. Він потрібен для шифрування, розшифрування
контейнерів ключів та хешування ГОСТ.

Швидкий старт
-------------

### Підпис і перевірка хешу (низький рівень)

```js
import gost89 from "gost89";
import * as jk from "jkurwa";

const algo = gost89.compat.algos();

const priv = jk.pkey("DSTU_PB_257", "40a0e1400001e091b160101150f1b1e0f1d14130e1c0b07011d120a04120c041d");
const pub = priv.pub();

const hash = algo.hash(Buffer.from("hello, world"));
const sign = priv.sign(hash, "le");

pub.verify(hash, sign, "le"); // => true
```

### Підпис документа (високий рівень)

`Box` поєднує ключі, сертифікати, списки ЦСК та об'єкт `algo` (хеш/шифр) і формує
готове CMS-повідомлення `signedData`.

```js
import gost89 from "gost89";
import * as jk from "jkurwa";

const box = new jk.Box({ algo: gost89.compat.algos() });
box.load({ priv, cert }); // priv: jk.Priv, cert: jk.Certificate

const message = await box.sign(data, /* роль */ null, null, { time });

// загорнути в транспортний конверт податкової
const transport = message.as_transport({
  EDRPOU: "1234567891",
  RCV_EMAIL: "user@tax.mail.com",
  DOC_TYPE: "3",
});
```

### Читання приватного ключа з контейнера

```js
import fs from "fs";
import gost89 from "gost89";
import * as jk from "jkurwa";

const store = jk.Priv.from_protected(
  fs.readFileSync("Key-6.dat"),
  "PASSWORD",
  gost89.compat.algos()
);
store.keys.forEach((key) => console.log(key.as_pem()));
```

Більше — у каталогах [`examples/`](./examples) та [`test/`](./test), а повний
застосунок — у репозиторії [dstucrypt/agent](https://github.com/dstucrypt/agent).

Хеш-функції
-----------

Підписи ДСТУ 4145 обчислюються над хешем повідомлення, і jkurwa підтримує обидва
українські стандарти хешування:

| Алгоритм | OID | Примітки |
|----------|-----|----------|
| ГОСТ 34.311-95 | `1.2.804.2.1.1.1.1.2.1` | застарілий за замовчуванням, через `gost89` |
| Купина-256 (ДСТУ 7564:2014) | `1.2.804.2.1.1.1.1.2.2.1` | через [`@li0ard/kupyna`](https://www.npmjs.com/package/@li0ard/kupyna) |
| Купина-384 / Купина-512 | `…2.2.2` / `…2.2.3` | для 384/512-бітних ключів |

**Автоматичний вибір.** Зі звичайним `Box` хеш обирається за сертифікатом
підписанта — Kupyna-сертифікат підписується Купиною, старий GOST-сертифікат —
ГОСТ 34.311, — а вхідне повідомлення перевіряється хешем, зазначеним у його
`digestAlgorithm`. Жодного налаштування не потрібно:

```js
const box = new jk.Box({ algo: gost89.compat.algos() });
box.load({ priv, cert });
await box.sign(data, null, null, {}); // GOST-ключ -> GOST, Kupyna-ключ -> Kupyna
```

**Примусовий хеш.** Задайте типовий для box або перевизначте на окремий виклик:

```js
new jk.Box({ algo, hashMethod: "kupyna" });       // типовий для кожного sign()
await box.sign(data, null, null, { hash: "gost" }); // перевизначити цей виклик
```

Допустимі значення: `"gost"`, `"kupyna"` (Купина-256), аліаси розмірів
`"kupyna-384"` / `"kupyna-512"`, `"auto"` (за замовчуванням) або власна теґована
функція хешу. Невідоме значення кидає `jk.Box.EHASH`.

Підтримувані формати
--------------------

* **Сертифікати** — X.509 v3 за профілем ДСТУ (див. посилання нижче).
* **Контейнери приватних ключів** — `Key-6.dat` (IIT), PBES2, PKCS#12 / PFX, JKS.
* **Повідомлення** — CMS `signedData` та `envelopedData`, транспортні конверти
  податкової `TRANSPORTABLE` / `UA1_SIGN`.
* **Протоколи PKI** — OCSP, TSP (RFC 3161), CMP.

Застереження щодо безпеки та відомі обмеження
---------------------------------------------

* jkurwa **не** гарантує обчислення за сталий час (constant-time).
* Перевірка підпису звіряє підпис із відкритим ключем. Вона **не** перевіряє
  ланцюжок сертифікатів X.509, доки не завантажено список ЦСК
  (`box.loadCAs(...)`). Деталі — у readme репозиторію
  [dstucrypt/agent](https://github.com/dstucrypt/agent).
* Парсинг X.509 навмисно поблажливий: узгодженість версії та полів
  (наприклад, розширення в сертифікаті v1) не перевіряється — так влаштовані
  реальні сертифікати ЦСК (див. `lib/spec/rfc3280.js`).
* Реалізація CMP часткова — змодельовано лише підмножину запитів/відповідей
  для отримання сертифікатів з ендпоінтів українських ЦСК
  (див. `lib/spec/rfc4210-cmp.js`).
* Діалект CMS/PKCS#7 відповідає «дикому» профілю податкової, а не суворому
  RFC 5652.
* Для незалежної перехресної перевірки підписів — <https://czo.gov.ua/verify>.

Про вразливості повідомляйте через [SECURITY.md](./SECURITY.md) — приватним
звітом GitHub, а не публічним issue.

Споріднені бібліотеки
---------------------

* [ukurwa4145](https://github.com/dstucrypt/ukurwa4145) — ДСТУ 4145 на Python;
* [gost89](https://github.com/dstucrypt/gost89) — шифр ГОСТ, хеш, MAC, загортання
  ключів і завантажувач контейнерів чистим JS;
* [python-gost89](https://github.com/dstucrypt/python-gost89) — хеш ГОСТ для Python;
* [jksreader](https://github.com/dstucrypt/jksreader) — парсер java-контейнерів
  ключів, які використовує ПриватБанк;
* [zozol](https://github.com/muromec/zozol) — парсер/серіалізатор ASN.1 для Python
  зі схемами X.509 та «дикого» CMS;
* [openssl-dstu](https://github.com/dstucrypt/openssl-dstu) — пропатчений OpenSSL
  з підтримкою ДСТУ 4145 і ГОСТ (застарілий, не підтримується).

Демо та застосунки
------------------

* <https://dstucrypt.github.io/signerbox2/> — демо в браузері;
* [dstucrypt/agent](https://github.com/dstucrypt/agent) — консольна утиліта й демон
  для підпису, шифрування та розшифрування файлів;
* [dstukeys](https://github.com/dstucrypt/dstukeys) — приклади веб-автентифікації;
* [e-rro](https://github.com/max1gu/e-rro) та
  [OpenPRRO](https://github.com/p2p-sys/OpenPRRO) — застосунки програмних РРО (ПРРО).

Посилання
---------

* Формат сертифіката (профіль X.509 v3): <http://zakon4.rada.gov.ua/laws/show/z1398-12>
* Формат контейнера приватного ключа (схожий на PBES2, чинний з 01.01.2016): <http://zakon3.rada.gov.ua/laws/show/z2227-13>
* Закон про електронні довірчі послуги: <http://zakon.rada.gov.ua/laws/show/2155-19>
* ДСТУ 7564:2014 (хеш-функція «Купина») — національний стандарт України.
* Формат податкової звітності та деталі реалізації: [dstucrypt/agent](https://github.com/dstucrypt/agent).

Ліцензія
--------

BSD. Автор оригіналу: Ilya Petrov.

Бонус
-----

Перше відоме вживання слова *Kurwa* зафіксовано 1415 року. З 600-річчям, Kurwa!
