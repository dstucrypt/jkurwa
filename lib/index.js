import models from './models/index.js';
import dstszi2010 from './spec/dstszi2010.js';
import rfc3280 from './spec/rfc3280.js';
import rfc3161 from './spec/rfc3161-tsp.js';
import Keycoder from './app/keycoder.js';
import Box from './app/ctx.js';
import * as base64 from './util/base64.js'; // consider changing this one to standart
import transport from './util/transport.js';
import standard from './standard.js';
import curve from './curve.js';

export default {
    b64_decode: base64.b64_decode,
    b64_encode: base64.b64_encode,
    Curve: curve.Curve,
    Field: curve.Field,
    pkey: curve.pkey,
    pubkey: curve.pubkey,
    std_curve: curve.std_curve,
    transport: transport,

    Priv: models.Priv,
    Pub: models.Pub,
    Certificate: models.Certificate,

    // curve definitions
    standard: standard,

    // submodules
    dstszi2010: dstszi2010,
    rfc3280: rfc3280,
    rfc3161: rfc3161,
    Keycoder: Keycoder,
    guess_parse: Keycoder.guess_parse,
    Box: Box,
    models: models,
};
