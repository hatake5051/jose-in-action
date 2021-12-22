import { isJWAJWSAlg, JWAJWSAlg, KtyFromJWAJWSAlg, ktyFromJWAJWSAlg } from 'jwa/sec3/alg';
import { isJWAJWEAlg, JWAJWEAlg, KtyFromJWAJWEAlg, ktyFromJWAJWEAlg } from 'jwa/sec4/alg';
import { isJWAEncAlg, JWAEncAlg, KtyFromJWAEncAlg } from 'jwa/sec5/encalg';
import { isJWAKty, JWAKty, JWAKtyList } from 'jwa/sec6/kty';
import { Alg } from './alg';

export { Kty, isKty, KtyList, KtyFromAlg, ktyFromAlg };

/**
 * Kty は JSON Web Key Types を列挙する。
 * 'OKP' は未実装である。
 */
type Kty = JWAKty;
const isKty = (arg: unknown): arg is Kty => isJWAKty(arg);

const KtyList = [...JWAKtyList] as const;

type KtyFromAlg<A extends Alg> = A extends JWAJWSAlg
  ? KtyFromJWAJWSAlg<A>
  : A extends JWAJWEAlg
  ? KtyFromJWAJWEAlg<A>
  : A extends JWAEncAlg
  ? KtyFromJWAEncAlg
  : never;

function ktyFromAlg<A extends Alg>(alg: A): KtyFromAlg<A> {
  if (isJWAJWSAlg(alg)) {
    return ktyFromJWAJWSAlg(alg) as KtyFromAlg<A>;
  }
  if (isJWAJWEAlg(alg)) {
    return ktyFromJWAJWEAlg(alg) as KtyFromAlg<A>;
  }
  if (isJWAEncAlg(alg)) {
    return 'oct' as KtyFromAlg<A>;
  }
  throw new TypeError(`${alg} に対応する鍵の kty がわからなかった`);
}
