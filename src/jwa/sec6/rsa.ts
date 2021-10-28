// --------------------BEGIN JWA RSA keys --------------------

import { CommomJWKParams, equalsCommonJWKParams, isCommonJWKParams } from 'jwk/common';
import { isObject } from 'utility';

export {
  RSAPublicKey,
  isRSAPublicKey,
  equalsRSAPublicKey,
  RSAPrivateKey,
  isRSAPrivateKey,
  equalsRSAPrivateKey,
  exportRSAPublicKey,
};

/**
 * RSA 公開鍵は JWK 共通パラメータと RSA 公開鍵パラメータからなる。
 */
type RSAPublicKey = CommomJWKParams<'RSA'> & RSAPublicKeyParams;

/**
 * 引数が RSA 公開鍵かどうか確認する。
 * kty == RSA かどうか、 n,e をパラメータとしてもつか確認する。
 */
const isRSAPublicKey = (arg: unknown): arg is RSAPublicKey =>
  isCommonJWKParams(arg) && arg.kty === 'RSA' && isRSAPublicKeyParams(arg);

function equalsRSAPublicKey(l?: RSAPublicKey, r?: RSAPublicKey): boolean {
  return equalsCommonJWKParams(l, r) && equalsRSAPublicKeyParams(l, r);
}

/**
 * RSA 秘密鍵は RSA 公開鍵に RSA 秘密鍵パラメータを加えたもの
 */
type RSAPrivateKey = RSAPublicKey & RSAPrivateKeyParams;

/**
 * 引数が RSA 秘密鍵かどうか確認する。
 * RSA 公開鍵であるか、また d をパラメータとして持つか確認する。
 */
const isRSAPrivateKey = (arg: unknown): arg is RSAPrivateKey =>
  isRSAPublicKey(arg) && isRSAPrivateKeyParams(arg);

function equalsRSAPrivateKey(l?: RSAPrivateKey, r?: RSAPrivateKey): boolean {
  return equalsRSAPublicKey(l, r) && equalsRSAPrivateKeyParams(l, r);
}

const exportRSAPublicKey = (priv: RSAPrivateKey): RSAPublicKey => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, p, q, dp, dq, qi, ...pub } = priv;
  return pub;
};

/**
 * RFC7518#6.3.1
 * RSA 公開鍵が持つパラメータを定義する。
 */
type RSAPublicKeyParams = {
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
const rsaPublicKeyParams = ['n', 'e'] as const;

const isRSAPublicKeyParams = (arg: unknown): arg is RSAPublicKeyParams =>
  isObject<RSAPublicKeyParams>(arg) && typeof arg.n === 'string' && typeof arg.e === 'string';

function equalsRSAPublicKeyParams(l?: RSAPublicKeyParams, r?: RSAPublicKeyParams): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  for (const n of rsaPublicKeyParams) {
    const ln = l[n];
    const rn = r[n];
    if (ln == null && rn == null) continue;
    if (ln == null || rn == null) return false;
    if (ln === rn) continue;
    return false;
  }
  return true;
}

/**
 * RFC7518#6.3.2
 * RSA 秘密鍵を表すために用いられる。
 * 面倒なので 6.3.2.7 は実装を省いた
 */
type RSAPrivateKeyParams = {
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
};

const rsaPrivateParams = ['d', 'p', 'q', 'dp', 'dq', 'qi'] as const;

const isRSAPrivateKeyParams = (arg: unknown): arg is RSAPrivateKeyParams =>
  isObject<RSAPrivateKeyParams>(arg) &&
  rsaPrivateParams.every((n) =>
    n === 'd' ? typeof arg[n] === 'string' : arg[n] == null || typeof arg[n] === 'string'
  );

function equalsRSAPrivateKeyParams(l?: RSAPrivateKeyParams, r?: RSAPrivateKeyParams): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  for (const n of rsaPrivateParams) {
    const ln = l[n];
    const rn = r[n];
    if (ln == null && rn == null) continue;
    if (ln == null || rn == null) return false;
    if (ln === rn) continue;
    return false;
  }
  return true;
}

// --------------------END JWA RSA keys --------------------
