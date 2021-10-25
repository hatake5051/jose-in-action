// --------------------BEGIN JWK definition --------------------

import { Kty } from '../iana';

export { JWK, JWKSet, isJWKSet, isJWK };

/**
 * RFC7517#4
 * JSON Web Key は暗号鍵を表現する JSON オブジェクト。
 * Kty がなんであるか、また非対称暗号鍵の場合は公開鍵か秘密鍵かで具体的な型を指定できる
 */
type JWK<K extends Kty, A extends AsymKty> = never;

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
  // TODO: JWK チェック関数の実装
  return false;
}

/**
 * RFC7517#5
 * JWK Set は複数の JWK を表現する JSON オブジェクトである。
 */
type JWKSet = {
  /**
   * RFC7517#5.1
   * keys parameter は JWK の配列を値としてもつ。
   * デフォルトでは、 JWK の順序は鍵の優先順位を表していないが、アプリケーションによっては持たせても良い。
   */
  keys: JWK<Kty, AsymKty>[];
};

/**
 * 引数が JWK Set かどうか判定する.
 * keys パラメータが存在して、その値が JWK の配列なら OK
 */
const isJWKSet = (arg: unknown): arg is JWKSet => {
  if (typeof arg !== 'object') return false;
  if (arg == null) return false;
  if ('keys' in arg) {
    const a = arg as { keys: unknown };
    if (Array.isArray(a.keys)) {
      const l = a.keys as Array<unknown>;
      for (const k of l) {
        if (!isJWK(k)) return false;
      }
      return true;
    }
  }
  return false;
};

/**
 * JWK が非対称鍵の場合、公開鍵か秘密鍵かのいずれかであるかを表す。
 */
type AsymKty = 'Pub' | 'Priv';

// --------------------END JWK definition --------------------
