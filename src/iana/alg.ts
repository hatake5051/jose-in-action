import { isJWAJWSAlg, JWAJWSAlg } from 'jwa/sec3/alg';
import { isJWAJWEAlg, JWAJWEAlg } from 'jwa/sec4/alg';
import { isJWAEncAlg, JWAEncAlg } from 'jwa/sec5/encalg';

export { Alg, isAlg, EncAlg, isEncAlg };

/**
 * Alg は暗号アルゴリズムを列挙する。
 * RFC7518 に定義されているもののみ今回は実装の対象としている。
 */
type Alg<T extends 'JWS' | 'JWE' = 'JWS' | 'JWE'> = T extends 'JWS'
  ? JWAJWSAlg
  : T extends 'JWE'
  ? JWAJWEAlg
  : never;

function isAlg<T extends 'JWS' | 'JWE'>(arg: unknown, t?: T): arg is Alg<T> {
  if (t === 'JWS') return isJWAJWSAlg(arg);
  if (t === 'JWE') return isJWAJWEAlg(arg);
  return isJWAJWSAlg(arg) || isJWAJWEAlg(arg);
}

type EncAlg = JWAEncAlg;
const isEncAlg = (arg: unknown): arg is EncAlg => isJWAEncAlg(arg);
