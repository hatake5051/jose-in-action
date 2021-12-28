import { isObject } from 'utility';
import { isJWK, JWK } from './jwk';

export { JWKSet, isJWKSet };

/**
 * [仕様] RFC7517#5
 * JWK Set は複数の JWK を表現する JSON オブジェクトである。
 */
type JWKSet = {
  /**
   * [仕様] RFC7517#5.1
   * keys parameter は JWK の配列を値としてもつ。
   */
  keys: JWK[];
};

const isJWKSet = (arg: unknown): arg is JWKSet =>
  isObject<JWKSet>(arg) && Array.isArray(arg.keys) && arg.keys.every((jwk) => isJWK(jwk));
