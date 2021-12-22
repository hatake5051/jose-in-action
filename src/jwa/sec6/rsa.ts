// --------------------BEGIN JWA RSA keys --------------------

import { isObject } from 'utility';

export {
  JWARSAPubKeyParams,
  isJWARSAPubKeyParams,
  equalsJWARSAPubKeyParams,
  JWARSAPrivKeyParams,
  isJWARSAPrivKeyParams,
  equalsJWARSAPrivKeyParams,
  exportJWARSAPubKeyParams,
};

/**
 * RFC7518#6.3.1
 * RSA 公開鍵が持つパラメータを定義する。
 */
type JWARSAPubKeyParams = {
  /**
   * RFC7518#6.3.1.1
   * n parameter は RSA 公開鍵の modulus値が BASE64URLUint エンコードされている。
   */
  n: string;
  /**
   * RFC7518#6.3.1.2
   * e parameter は RSA 公開鍵の exponent 値が BASE64URLUint エンコードされている
   */
  e: string;
};
const JWARSAPubKeyParamNames = ['n', 'e'] as const;

const isPartialJWARSAPubKeyParams = (arg: unknown): arg is Partial<JWARSAPubKeyParams> =>
  isObject<JWARSAPubKeyParams>(arg) &&
  JWARSAPubKeyParamNames.every((n) => arg[n] == null || typeof arg[n] === 'string');

const isJWARSAPubKeyParams = (arg: unknown): arg is JWARSAPubKeyParams =>
  isPartialJWARSAPubKeyParams(arg) && JWARSAPubKeyParamNames.every((n) => arg[n] != null);

function equalsJWARSAPubKeyParams(
  l?: Partial<JWARSAPubKeyParams>,
  r?: Partial<JWARSAPubKeyParams>
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  return JWARSAPubKeyParamNames.every((n) => l[n] === r[n]);
}

/**
 * RFC7518#6.3.2
 * RSA 秘密鍵を表すために用いられる。
 * 面倒なので 6.3.2.7 は実装を省いた
 */
type JWARSAPrivKeyParams = {
  /**
   * RFC7518#6.3.2.1
   * d parameter は RSA 秘密鍵の private exponent 値を持つ。
   * 値は BASE64URLUint エンコードされている
   */
  d: string;
  /**
   * RFC7518#6.3.2.2
   * p parameter は RSA 秘密鍵の first prime factor 値を持つ。
   * 値は BASE64URLUint エンコードされている
   */
  p?: string;
  /**
   * RFC7518#6.3.2.3
   * q parameter は RSA 秘密鍵の second prime factor 値を持つ。
   * 値は BASE64URLUint エンコードされている
   */
  q?: string;
  /**
   * RFC7518#6.3.2.4
   * dp parameter は RSA 秘密鍵の first factor CRT exponent 値を持つ。
   * 値は BASE64URLUint エンコードされている
   */
  dp?: string;
  /**
   * RFC7518#6.3.2.5
   * dq parameter は RSA 秘密鍵の second factor CRT exponent 値を持つ。
   * 値は BASE64URLUint エンコードされている
   */
  dq?: string;
  /**
   * RFC7518#6.3.2.6
   * qi parameter は RSA 秘密鍵の first CRT coefficient 値を持つ。
   * 値は BASE64URLUint エンコードされている
   */
  qi?: string;
} & JWARSAPubKeyParams;

const JWARSAPrivKeyParamNames = [
  'd',
  'p',
  'q',
  'dp',
  'dq',
  'qi',
  ...JWARSAPubKeyParamNames,
] as const;

const isPartialJWARSAPrivKeyParams = (arg: unknown): arg is Partial<JWARSAPrivKeyParams> =>
  isObject<JWARSAPrivKeyParams>(arg) &&
  JWARSAPrivKeyParamNames.every((n) => arg[n] == null || typeof arg[n] === 'string');

const isJWARSAPrivKeyParams = (arg: unknown): arg is JWARSAPrivKeyParams =>
  isPartialJWARSAPrivKeyParams(arg) && arg.d != null;

function equalsJWARSAPrivKeyParams(
  l?: Partial<JWARSAPrivKeyParams>,
  r?: Partial<JWARSAPrivKeyParams>
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  return JWARSAPrivKeyParamNames.every((n) => l[n] === r[n]);
}

function exportJWARSAPubKeyParams(priv: JWARSAPrivKeyParams): JWARSAPubKeyParams {
  let pub: Partial<JWARSAPubKeyParams> = {};
  JWARSAPubKeyParamNames.forEach((n) => {
    pub = { ...pub, [n]: priv[n] };
  });
  if (isJWARSAPubKeyParams(pub)) return pub;
  throw new TypeError('JWARSAPrivKeyParams から公開鍵情報を取り出せませんでした');
}

// --------------------END JWA RSA keys --------------------
