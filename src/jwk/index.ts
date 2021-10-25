// --------------------BEGIN JWK definition --------------------

import { Kty } from '../iana';
import { isCommonJWKParams } from './internal/common';
import { ECPrivateKey, ECPublicKey, isECPrivateKey, isECPublicKey } from './internal/ec';
import { isOctKey, octKey } from './internal/oct';
import { isRSAPrivateKey, isRSAPublicKey, RSAPrivateKey, RSAPublicKey } from './internal/rsa';

export { JWK, JWKSet, isJWKSet, isJWK };

/**
 * RFC7517#4
 * JSON Web Key は暗号鍵を表現する JSON オブジェクト。
 * Kty がなんであるか、また非対称暗号鍵の場合は公開鍵か秘密鍵かで具体的な型を指定できる
 */
type JWK<K extends Kty, A extends AsymKty> = K extends 'oct'
  ? octKey
  : K extends 'EC'
  ? A extends 'Pub'
    ? ECPublicKey
    : A extends 'Priv'
    ? ECPrivateKey
    : ECPublicKey | ECPrivateKey
  : K extends 'RSA'
  ? A extends 'Pub'
    ? RSAPublicKey
    : A extends 'Priv'
    ? RSAPrivateKey
    : RSAPublicKey | RSAPrivateKey
  : never;

/**
 * 引数が JWK オブジェクトであるかどうか確認する。
 * kty を指定するとその鍵タイプの JWK 形式を満たすか確認する。
 * asym を指定すると非対称暗号鍵のうち指定した鍵（公開鍵か秘密鍵）かであるかも確認する。
 */
function isJWK<K extends Kty, A extends AsymKty>(
  arg: unknown,
  kty?: K,
  asym?: A
): arg is JWK<K, A> {
  switch (kty) {
    // kty を指定しないときは、最低限 JWK が持つべき情報を持っているか確認する
    case undefined:
      return isCommonJWKParams(arg);
    case 'oct':
      return isOctKey(arg);
    case 'EC':
      if (asym === undefined) return isECPublicKey(arg) || isECPrivateKey(arg);
      if (asym === 'Pub') return isECPublicKey(arg);
      return isECPrivateKey(arg);
    case 'RSA':
      if (asym === undefined) return isRSAPublicKey(arg) || isRSAPrivateKey(arg);
      if (asym === 'Pub') return isRSAPublicKey(arg);
      return isRSAPrivateKey(arg);
    default:
      return false;
  }
}

/**
 * RFC7517#5
 * JWK Set は複数の JWK を表現する JSON オブジェクトである。
 */
type JWKSet = {
  // TODO: RFC7517 Section5.1 に基づいて JWK Set を定義する
};

/**
 * 引数が JWK Set かどうか判定する.
 */
const isJWKSet = (arg: unknown): arg is JWKSet => {
  // TODO: RFC7517 Section5.1 に基づいて JWK Set をチェックする
  return false;
};

/**
 * JWK が非対称鍵の場合、公開鍵か秘密鍵かのいずれかであるかを表す。
 */
type AsymKty = 'Pub' | 'Priv';

// --------------------END JWK definition --------------------
