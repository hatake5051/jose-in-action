// --------------------BEGIN JWS MAC algorithms --------------------

import { Alg, KtyFromAlg } from 'iana';
import { JWK } from 'jwk';
import { JWSSignature } from './types';

export { MACOperator };

/**
 * MAC アルゴリズムのインターフェースを定義する。
 */
interface MACOperator<A extends Alg> {
  mac: (alg: A, key: JWK<KtyFromAlg<A>>, m: Uint8Array) => Promise<JWSSignature>;
  verify: (alg: A, key: JWK<KtyFromAlg<A>>, m: Uint8Array, mac: JWSSignature) => Promise<boolean>;
}

// --------------------END JWS MAC algorithms --------------------
