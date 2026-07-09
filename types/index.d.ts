/*
 * Hand-written type declarations for the jkurwa public API.
 *
 * Coverage is intentionally limited to what a consumer of the package calls:
 * Box, load(), pkey/pubkey/std_curve, Priv, Pub, Certificate, transport,
 * guess_parse and the error classes. Deep internals (field arithmetic,
 * ASN.1 spec entities) are exposed as opaque types — their shapes are
 * dynamic and typing them precisely would risk lying to the compiler.
 */

import { Buffer } from "buffer";

// ---------------------------------------------------------------------------
// Opaque internals
// ---------------------------------------------------------------------------

/** GF(2^m) field element. Opaque: use Curve/Priv/Pub methods instead. */
export class Field {
  private _opaque_field: unknown;
}

/** Point on a DSTU 4145 curve. Opaque. */
export class Point {
  private _opaque_point: unknown;
}

/** An asn1.js-defined entity: only encode/decode are stable API. */
export interface Asn1Entity {
  encode(obj: any, enc: "der" | "pem" | string): Buffer;
  decode(data: Buffer, enc: "der" | "pem" | string, options?: any): any;
}

/** A big number as produced by asn1.js (bn.js BN instance). */
export type BigNum = any;

/**
 * Algorithm bundle, normally `gost89.compat.algos()`. All members are
 * optional because a Box created only for verification needs just `hash`.
 */
export interface Algo {
  hash?: HashFn;
  kdf?: (input: Buffer) => Buffer;
  keywrap?: (kek: Buffer, cek: Buffer, iv: Buffer) => Buffer;
  keyunwrap?: (kek: Buffer, wcek: Buffer, iv: Buffer) => Buffer;
  encrypt?: (data: Buffer, cek: Buffer, iv: Buffer) => Buffer;
  decrypt?: (data: Buffer, cek: Buffer, iv: Buffer) => Buffer;
  storesave?: (...args: any[]) => any;
  storeload?: (...args: any[]) => any;
  [key: string]: unknown;
}

/**
 * A hash function. May carry an `algo` tag with the digest OID name
 * ("Dstu7564-256" etc.); untagged functions are treated as GOST 34.311.
 */
export interface HashFn {
  (data: Buffer): Buffer;
  algo?: string;
}

/**
 * Hash selector accepted by `new Box({hashMethod})` and `sign(..., {hash})`:
 * a friendly alias, a digest OID name, "auto" (pick from the signer
 * certificate) or a tagged hash function.
 */
export type HashChoice =
  | "gost"
  | "kupyna"
  | "kupyna-384"
  | "kupyna-512"
  | "auto"
  | string
  | HashFn;

/** Network transport callback used for TSP/OCSP/CMP queries. */
export type QueryFn = (...args: any[]) => any;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Thrown by deprecated APIs (also available as `Box.EOLD`). */
export class EOLD extends Error {
  static silent: boolean;
}

/** Thrown when an unknown/unavailable hash is requested for signing. */
export class EHASH extends Error {}

// ---------------------------------------------------------------------------
// Curves and keys
// ---------------------------------------------------------------------------

export class Curve {
  static from_id(name: string): Curve;
  static from_asn1(curve: any, fmt?: string): Curve;
  static resolve(def: { type: "params" | "id"; value: any }, fmt?: string): Curve;

  m: number;
  order: Field;
  base: Point;

  pkey(inp: Buffer | string | Field, fmt?: string): Priv;
  pubkey(inp: Buffer | string | Field, inputFmt?: string): Pub;
  keygen(): Priv;
  rand(): Field;
  point(px: any, py?: any): Point;
  contains(p: Point): boolean;
  equals(other: Curve): boolean;
  name(): string | undefined;
  curve_id(): number | undefined;
  as_struct(): any;
}

/** Signature in split form: field elements `s` and `r`. */
export interface SplitSign {
  s: Field;
  r: Field;
  hash?: Field;
}

export type SignFormat = "short" | "le";

export class Priv {
  type: "Priv";
  d: Field;
  curve: Curve;
  algorithm: string;

  constructor(curve: Curve, param_d: Field | Buffer);

  sign(hash: Buffer): SplitSign;
  sign(hash: Buffer, fmt: SignFormat): Buffer;
  pub(): Pub;
  pub_match(pubKey: Pub | Field | Buffer): boolean;
  derive(pubkey: Pub | Field): Buffer;
  sharedKey(pubkey: Pub | Field, ukm: Buffer, kdf: (input: Buffer) => Buffer): Buffer;
  decrypt(
    data: Buffer,
    pubkey: Pub | { pubkey: Pub },
    param: { ukm: Buffer; wcek: Buffer; iv: Buffer },
    algo: Algo
  ): Buffer;
  encrypt(
    data: Buffer,
    cert: { pubkey: Pub },
    algo: Algo
  ): { iv: Buffer; wcek: Buffer; data: Buffer; ukm: Buffer };

  as_pem(): string;
  to_pem(): string;
  as_asn1(): Buffer;
  to_asn1(): Buffer;
  to_pbes2(password: Buffer | string, algo: Algo): Buffer;

  static from_asn1(data: Buffer): Priv;
  static from_asn1(data: Buffer, returnStore: true): PrivStore;
  static from_pem(data: string | Buffer): Priv;
  static from_pem(data: string | Buffer, returnStore: true): PrivStore;
  static from_protected(
    data: Buffer,
    password?: Buffer | string | null,
    algo?: Algo
  ): { certs: Certificate[]; keys: Priv[]; format: "privkeys" };
  static sign_serialise(data: SplitSign, fmt: SignFormat): Buffer;
}

export interface PrivStore {
  keys: Priv[];
  format: "privkeys";
}

export class Pub {
  type: "Pub";
  x: Field;
  y: Field;
  point: Point;
  curve: Curve;

  constructor(curve: Curve, point: Point, compressed?: Buffer | Field);

  verify(
    hash: Buffer | Field,
    sign: Buffer | string | SplitSign,
    fmt?: SignFormat | "split"
  ): boolean;
  validate(): boolean;
  compress(): Buffer;
  serialize(): Buffer;
  keyid(algos: { hash: HashFn }): Buffer;
}

export function pkey(curveName: string, keyData: Buffer | string, keyFmt?: string): Priv;
export function pubkey(curveName: string, keyData: Buffer | string, keyFmt?: string): Pub;
export function std_curve(name: string): Curve;

// ---------------------------------------------------------------------------
// Certificate
// ---------------------------------------------------------------------------

export interface CertExtensions {
  ipn: Record<string, string> | null;
  authorityInfoAccess: { id: string; link: string } | null;
  subjectInfoAccess: { id: string; link: string } | null;
  subjectKeyIdentifier: Buffer | null;
  authorityKeyIdentifier: Buffer | null;
  [key: string]: unknown;
}

/** Plain-object view of a certificate as returned by `as_dict()`. */
export interface CertDict {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  extension: {
    ipn: Record<string, string> | null;
    authorityInfoAccess: any;
    subjectInfoAccess: any;
    subjectKeyIdentifier: string | null;
    authorityKeyIdentifier: string | null;
  };
  usage: { sign: boolean; encrypt: boolean };
  valid: { from: number; to: number };
  /** Present in Box.unwrap output when a CA store is loaded. */
  verified?: boolean;
}

export class Certificate {
  format: "x509";
  curve: Curve | null;
  valid: { from: number; to: number };
  serial: BigNum;
  signatureAlgorithm: string;
  pubkeyAlgorithm: string;
  extension: CertExtensions;
  issuer: Record<string, string>;
  subject: Record<string, string>;
  pubkey?: Pub;
  trusted?: boolean;
  ob: any;

  constructor(cert: any, lazy?: boolean);

  static from_asn1(data: Buffer): Certificate;
  static from_pem(data: string | Buffer): Certificate;
  static formatDN(rdnList: any): string;
  static signCert(opts: { privkey: Priv; hash: HashFn; certData: any }): Certificate;

  verify(
    opts: { time: number | Date; usage?: string },
    hashes: Record<string, HashFn>,
    lookupFn: (dn: string, keyId?: Buffer) => Certificate | null
  ): boolean;
  verifyTime(time: number): boolean;
  verifySignature(pubkey: Pub, hashes: Record<string, HashFn>): boolean;
  canUseFor(op: string): boolean;
  getCompleteChain(
    lookupFn: (dn: string, keyId?: Buffer) => Certificate | null
  ): Certificate[];
  pubkey_unpack(): Pub;

  as_asn1(): Buffer;
  to_asn1(): Buffer;
  as_pem(): string;
  to_pem(): string;
  as_dict(): CertDict;
  nameSerial(): { issuer: any; serialNumber: BigNum };
  rdnSerial(): string;
  isRoot(): boolean;
  issuerDN(): string;
  subjectDN(): string;
  readonly ocspLink: string | null;
}

// ---------------------------------------------------------------------------
// Message (reachable as models.Message)
// ---------------------------------------------------------------------------

export class Message {
  static ENOCERT: { new (): Error & { code: "ENOCERT" } };

  type: "signedData" | "envelopedData" | "data" | string;
  info: any;

  constructor(data: Buffer | object);

  as_asn1(): Buffer;
  as_transport(opts?: any, addCert?: boolean): Buffer;
  verify(
    hash: HashFn,
    lookupCert: (certs: Certificate[], query: any) => Certificate | null,
    lookupCA: (dn: string, keyId?: Buffer) => Certificate | null,
    opts?: any
  ): boolean | Promise<boolean>;
  signer(lookupCert?: any): Certificate;
  decrypt(
    crypter: Priv,
    algo: Algo,
    lookupCert?: (certs: Certificate[], query: any) => Certificate | null
  ): Buffer;

  readonly digestAlgo: string;
  readonly signature: Buffer;
  readonly contentTime: number | null;
  readonly tokenTime: number | null;
}

// ---------------------------------------------------------------------------
// Box
// ---------------------------------------------------------------------------

/** One entry of `new Box({keys})` / `box.load()`. */
export interface KeyInfo {
  priv?: Priv;
  cert?: Certificate;
  privPem?: string | Buffer;
  certPem?: string | Buffer;
  /** Raw contents of Key-6.dat / PBES2 / PKCS#12 / JKS containers. */
  keyBuffers?: Buffer[];
  certBuffers?: Array<string | Buffer>;
  /** @deprecated pass keyBuffers instead (throws EOLD unless EOLD.silent) */
  privPath?: string | string[];
  /** @deprecated pass certBuffers instead */
  certPath?: string | string[];
  password?: Buffer | string;
}

export interface BoxOptions {
  algo?: Algo;
  keys?: KeyInfo[];
  /** DER bundle of CA certificates to verify chains against. */
  casBuffer?: Buffer;
  /** Default hash for signing; "auto"/unset picks it from the certificate. */
  hashMethod?: HashChoice | null;
  /** Network callback for TSP/OCSP/CMP requests. */
  query?: QueryFn | null;
}

export interface SignOpts {
  /** Omit the content from the signed message. */
  detached?: boolean;
  /** Request timestamps: true/"signature" or "content" or "all". */
  tsp?: boolean | "content" | "signature" | "all";
  /** Signing time override. */
  time?: number | Date;
  /** Embed the certificate chain ("ref" embeds references only). */
  includeChain?: boolean | "ref";
  ocsp?: boolean | "ref";
  /** Per-call hash override (see HashChoice). */
  hash?: HashChoice;
}

export interface PipeCommand extends SignOpts {
  op: "sign" | "encrypt";
  role?: string | null;
  forCert?: Certificate | string;
  /** Wrap the result into the tax-office transport envelope. */
  tax?: boolean;
  addCert?: boolean;
}

export type PipeError = "ENODATA" | "ENOCERT" | "ESIGN" | "EOCSP" | "ENOKEY";

export type UnwrapPipeStep =
  | { transport: true; headers: Record<string, string> }
  | {
      error: PipeError;
      signed?: true;
      broken_sign?: true;
      broken_cert?: true;
      enc?: true;
    }
  | {
      signed: true;
      cert: CertDict;
      ocsp?: any[];
      signingTime?: number;
      contentTime?: number | null;
      tokenTime?: number | null;
    }
  | { enc: true };

export interface UnwrapInfo {
  /** Final decoded payload (absent when the pipeline errored early). */
  content?: Buffer;
  /** Set when the last pipeline stage failed. */
  error?: PipeError;
  pipe: UnwrapPipeStep[];
}

export interface UnwrapOpts {
  ocsp?: boolean | "lax";
  tsp?: boolean | "content" | "signature" | "all";
}

export class Box {
  static load: typeof load;
  static EOLD: typeof EOLD;
  static EHASH: typeof EHASH;

  algo: Algo;
  keys: Array<{ priv?: Priv; cert?: Certificate }>;
  hashMethod: HashChoice | null;
  query: QueryFn | null;

  constructor(opts?: BoxOptions);

  load(keyinfo: KeyInfo): void;
  loadCAs(buffer: Buffer): void;
  loadCertsCmp(url: string): Promise<number>;
  findCertsCmp(urlsHint?: string[]): Promise<number>;

  keyFor(op: "sign" | "encrypt", role?: string | null): { priv: Priv; cert: Certificate };

  sign(
    data: Buffer,
    role: string | null | undefined,
    unusedCert: unknown,
    opts: SignOpts
  ): Promise<Message>;
  encrypt(
    data: Buffer,
    role: string | null | undefined,
    forCert: Certificate,
    opts?: any
  ): Message;
  pipe(data: Buffer, commands: Array<PipeCommand | string>, opts?: any): Promise<Buffer>;
  unwrap(data: Buffer, content?: Buffer, opts?: UnwrapOpts): Promise<UnwrapInfo>;

  lookupCA(query: string, keyId?: Buffer): Certificate | null;
  verifyCert(cert: Certificate, time: number, usage?: string): boolean;
  add(part: { cert?: Certificate; priv?: Priv }): void;
}

export default Box;

// ---------------------------------------------------------------------------
// Loaders and helpers
// ---------------------------------------------------------------------------

/** Parse key material into `{priv}` / `{cert}` entries (synchronous). */
export function load(
  keyinfo: KeyInfo,
  algo?: Algo
): Array<{ priv?: Priv; cert?: Certificate }>;

/**
 * Try every known container parser (keystore, PBES2, PFX, raw key,
 * certificate) and return whatever matched first. Throws on unknown input.
 */
export function guess_parse(data: Buffer | string): any;

export function b64_encode(
  data: Buffer,
  opts?: { line?: number; pad?: boolean }
): string;
export function b64_decode(data: string): Buffer;

export interface TransportDocument {
  type: string;
  contents: Buffer;
  encoding?: string;
}

declare const transport: {
  encode(
    documents: Array<{ type: string; contents: Buffer | string }>,
    headers?: Record<string, string>
  ): Buffer;
  decode(buffer: Buffer): { docs: TransportDocument[]; header?: Record<string, string> };
};
export { transport };

/** @deprecated use guess_parse / Priv.from_* / Certificate.from_* directly */
export class Keycoder {
  is_valid(data: Buffer | string): boolean;
  parse(data: Buffer | string): any;
}

export declare const models: {
  Certificate: typeof Certificate;
  Message: typeof Message;
  Priv: typeof Priv;
  Pub: typeof Pub;
};

// ASN.1 spec namespaces — dynamic asn1.js entities; only encode/decode are
// stable. Access concrete entities via index signature.
export declare const dstszi2010: Record<string, Asn1Entity | any>;
export declare const rfc3280: Record<string, Asn1Entity | any>;
export declare const rfc3161: Record<string, Asn1Entity | any>;

/** Standard curve parameter definitions (DSTU_PB_257, DSTU_PB_431, ...). */
export declare const standard: Record<string, any>;
