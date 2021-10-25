// --------------------BEGIN JWK RSA parameters --------------------

import { CommomJWKParams, isCommonJWKParams } from './common';

export { RSAPublicKey, isRSAPublicKey, RSAPrivateKey, isRSAPrivateKey };

/**
 * RSA 公開鍵は JWK 共通パラメータと RSA 公開鍵パラメータからなる。
 */
type RSAPublicKey = CommomJWKParams<'RSA'> & RSAPublicKeyParams;

/**
 * 引数が RSA 公開鍵かどうか確認する。
 * kty == RSA かどうか、 n,e をパラメータとしてもつか確認する。
 */
const isRSAPublicKey = (arg: unknown): arg is RSAPublicKey => {
  if (!isCommonJWKParams(arg) || arg.kty !== 'RSA') return false;
  return rsaPublicKeyParams.every((s) => s in arg);
};

/**
 * RSA 秘密鍵は RSA 公開鍵に RSA 秘密鍵パラメータを加えたもの
 */
type RSAPrivateKey = RSAPublicKey & RSAPrivateKeyParams;

/**
 * 引数が RSA 秘密鍵かどうか確認する。
 * RSA 公開鍵であるか、また d をパラメータとして持つか確認する。
 */
const isRSAPrivateKey = (arg: unknown): arg is RSAPrivateKey => {
  if (!isRSAPublicKey(arg)) return false;
  return 'd' in arg;
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
const rsaPublicKeyParams = ['n', 'e'];

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

// --------------------END JWK RSA parameters --------------------
