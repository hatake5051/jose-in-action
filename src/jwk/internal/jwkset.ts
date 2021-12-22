import { isObject } from 'utility';
import { isJWK, JWK } from './jwk';

export { JWKSet, isJWKSet };

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
  keys: JWK[];
};

const isJWKSet = (arg: unknown): arg is JWKSet =>
  isObject<JWKSet>(arg) && Array.isArray(arg.keys) && arg.keys.every((jwk) => isJWK(jwk));
