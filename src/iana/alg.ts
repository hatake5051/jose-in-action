import {
  isJWAMACAlg,
  isJWANoneAlg,
  isJWASigAlg,
  JWAMACAlg,
  JWANoneAlg,
  JWASigAlg,
} from 'jwa/sec3/alg';
import {
  isJWADEAlg,
  isJWADKAAlg,
  isJWAKAKWAlg,
  isJWAKEAlg,
  isJWAKWAlg,
  JWADEAlg,
  JWADKAAlg,
  JWAKAKWAlg,
  JWAKEAlg,
  JWAKWAlg,
} from 'jwa/sec4/alg';
import { isJWAEncAlg, JWAEncAlg } from 'jwa/sec5/encalg';

export { Alg, isAlg, EncAlg, isEncAlg };

/**
 * Alg は暗号アルゴリズムを列挙する。
 * RFC7518 に定義されているもののみ今回は実装の対象としている。
 */
type Alg<T extends 'JWS' | 'JWE' = 'JWS' | 'JWE'> = T extends 'JWS'
  ? JWASigAlg | JWAMACAlg | JWANoneAlg
  : T extends 'JWE'
  ? JWAKEAlg | JWAKWAlg | JWADKAAlg | JWAKAKWAlg | JWADEAlg
  : never;

function isAlg<T extends 'JWS' | 'JWE'>(arg: unknown, t?: T): arg is Alg<T> {
  const isJWSAlg = (arg: unknown): arg is Alg<'JWS'> =>
    isJWASigAlg(arg) || isJWAMACAlg(arg) || isJWANoneAlg(arg);
  const isJWEAlg = (arg: unknown): arg is Alg<'JWE'> =>
    isJWAKEAlg(arg) || isJWAKWAlg(arg) || isJWADKAAlg(arg) || isJWAKAKWAlg(arg) || isJWADEAlg(arg);
  if (t === 'JWS') return isJWSAlg(arg);
  if (t === 'JWE') return isJWEAlg(arg);
  return isJWSAlg(arg) || isJWEAlg(arg);
}

type EncAlg = JWAEncAlg;
const isEncAlg = (arg: unknown): arg is EncAlg => isJWAEncAlg(arg);
