// --------------------BEGIN JWK RSA parameters --------------------

import { CommomJWKParams, isCommonJWKParams } from './common';

export { RSAPublicKey, isRSAPublicKey, RSAPrivateKey, isRSAPrivateKey };

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
const rsaPrivateKeyParams = ['d', 'p', 'q', 'dp', 'dq', 'di'];

type RSAPublicKey = CommomJWKParams<'RSA'> & RSAPublicKeyParams;

const isRSAPublicKey = (arg: unknown): arg is RSAPublicKey => {
  if (!isCommonJWKParams(arg) || arg.kty !== 'RSA') return false;
  return rsaPublicKeyParams.every((s) => s in arg);
};
type RSAPrivateKey = RSAPublicKey & RSAPrivateKeyParams;

const isRSAPrivateKey = (arg: unknown): arg is RSAPrivateKey => {
  if (!isRSAPublicKey(arg)) return false;
  return 'd' in arg;
};

// --------------------END JWK RSA parameters --------------------
