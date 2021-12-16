import {
  isJWAMACAlg,
  isJWANoneAlg,
  isJWASigAlg,
  JWAMACAlg,
  JWANoneAlg,
  JWASigAlg,
  KtyFromJWAJWSAlg,
  ktyFromJWAJWSAlg,
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
  KtyFromJWAJWEAlg,
  ktyFromJWAJWEAlg,
} from 'jwa/sec4/alg';
import { isJWAEncAlg, JWAEncAlg, KtyFromJWAEncAlg } from 'jwa/sec5/encalg';
import { isJWAKty, JWAKty } from 'jwa/sec6/kty';
import { Alg } from './alg';

export { Kty, isKty, KtyFromAlg, ktyFromAlg };

/**
 * Kty は JSON Web Key Types を列挙する。
 * 'OKP' は未実装である。
 */
type Kty = JWAKty;
const isKty = (arg: unknown): arg is Kty => isJWAKty(arg);

type KtyFromAlg<A extends Alg> = A extends JWASigAlg | JWAMACAlg | JWANoneAlg
  ? KtyFromJWAJWSAlg<A>
  : A extends JWAKEAlg | JWAKWAlg | JWADKAAlg | JWAKAKWAlg | JWADEAlg
  ? KtyFromJWAJWEAlg<A>
  : A extends JWAEncAlg
  ? KtyFromJWAEncAlg
  : never;

function ktyFromAlg<A extends Alg>(alg: A): KtyFromAlg<A> {
  if (isJWASigAlg(alg) || isJWAMACAlg(alg) || isJWANoneAlg(alg)) {
    return ktyFromJWAJWSAlg(alg) as KtyFromAlg<A>;
  }
  if (
    isJWAKEAlg(alg) ||
    isJWAKWAlg(alg) ||
    isJWADKAAlg(alg) ||
    isJWAKAKWAlg(alg) ||
    isJWADEAlg(alg)
  ) {
    return ktyFromJWAJWEAlg(alg) as KtyFromAlg<A>;
  }
  if (isJWAEncAlg(alg)) {
    return 'oct' as KtyFromAlg<A>;
  }
  throw new TypeError(`${alg} に対応する鍵の kty がわからなかった`);
}
