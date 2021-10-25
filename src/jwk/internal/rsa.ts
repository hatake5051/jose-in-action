// --------------------BEGIN JWK RSA parameters --------------------

import { CommomJWKParams } from './common';

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
  // TODO: RFC7518 Section6.3.1 に基づいて公開鍵チェックを実装
  return false;
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
  // TODO: RFC7518 Section6.3.2 に基づいて秘密鍵チェックを実装
  return false;
};

/**
 * RFC7518#6.3.1
 * RSA 公開鍵が持つパラメータを定義する。
 */
type RSAPublicKeyParams = {
  // TODO: RFC7518 Section6.3.1 に基づいて公開鍵パラメータを定義
};
const rsaPublicKeyParams = [
  /* TODO: RFC7518 Section6.3.1 *に基づいて公開鍵パラメータを列挙 */
];

/**
 * RFC7518#6.3.2
 * RSA 秘密鍵を表すために用いられる。
 * 面倒なので 6.3.2.7 は実装を省いた
 */
type RSAPrivateKeyParams = {
  // TODO: RFC7518 Section6.3.2 に基づいて秘密鍵を定義
};

// --------------------END JWK RSA parameters --------------------
