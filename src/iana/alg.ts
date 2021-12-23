import { ESAlg, isESAlg } from 'jwa/sec3/es/alg';
import { HSAlg, isHSAlg } from 'jwa/sec3/hmac/alg';
import { isPSAlg, isRSAlg, PSAlg, RSAlg } from 'jwa/sec3/rsa/alg';
import { isJWAJWEAlg, JWAJWEAlg, KtyFromJWAJWEAlg, ktyFromJWAJWEAlg } from 'jwa/sec4/alg';
import { isJWAEncAlg, JWAEncAlg, KtyFromJWAEncAlg } from 'jwa/sec5/encalg';

export { Alg, isAlg, EncAlg, isEncAlg, KtyFromAlg, ktyFromAlg };

/**
 * Alg は暗号アルゴリズムを列挙する。
 */
type Alg<T extends 'JWS' | 'JWE' = 'JWS' | 'JWE'> = T extends 'JWS'
  ? JWSAlg
  : T extends 'JWE'
  ? JWAJWEAlg
  : never;

function isAlg<T extends 'JWS' | 'JWE'>(arg: unknown, t?: T): arg is Alg<T> {
  if (t === 'JWS') return isJWSAlg(arg);
  if (t === 'JWE') return isJWAJWEAlg(arg);
  return isJWSAlg(arg) || isJWAJWEAlg(arg);
}

type EncAlg = JWAEncAlg;
const isEncAlg = (arg: unknown): arg is EncAlg => isJWAEncAlg(arg);

type KtyFromAlg<A extends Alg> = A extends JWSAlg
  ? KtyFromJWSAlg<A>
  : A extends JWAJWEAlg
  ? KtyFromJWAJWEAlg<A>
  : A extends JWAEncAlg
  ? KtyFromJWAEncAlg
  : never;

function ktyFromAlg<A extends Alg>(alg: A): KtyFromAlg<A> {
  if (isJWSAlg(alg)) {
    return ktyFromJWSAlg(alg) as KtyFromAlg<A>;
  }
  if (isJWAJWEAlg(alg)) {
    return ktyFromJWAJWEAlg(alg) as KtyFromAlg<A>;
  }
  if (isJWAEncAlg(alg)) {
    return 'oct' as KtyFromAlg<A>;
  }
  throw new TypeError(`${alg} に対応する鍵の kty がわからなかった`);
}

type JWSAlg = RSAlg | PSAlg | ESAlg | HSAlg | 'none';

function isJWSAlg(arg: unknown): arg is JWSAlg {
  const list = [isRSAlg, isPSAlg, isESAlg, isHSAlg, (x: unknown) => x === 'none'];
  return list.some((f) => f(arg));
}

type KtyFromJWSAlg<A extends JWSAlg> = A extends RSAlg | PSAlg
  ? 'RSA'
  : A extends ESAlg
  ? 'EC'
  : A extends HSAlg
  ? 'oct'
  : never;

function ktyFromJWSAlg<A extends JWSAlg>(alg: A): KtyFromJWSAlg<A> {
  if (isPSAlg(alg) || isRSAlg(alg)) return 'RSA' as KtyFromJWSAlg<A>;
  if (isESAlg(alg)) return 'EC' as KtyFromJWSAlg<A>;
  if (isHSAlg(alg)) return 'oct' as KtyFromJWSAlg<A>;
  if (alg === 'none') throw new TypeError('none alg で鍵は使わない');
  throw new TypeError(`${alg} は JWA で定義された JWS の Alg ではない`);
}
