// --------------------BEGIN JWS Digital Signature algorithms --------------------

import { Alg, KtyFromAlg } from 'iana';
import { JWK } from 'jwk';
import { JWSSignature } from './types';

export { SigOperator };

/**
 * 署名アルゴリズムのインターフェースを定義する。
 */
interface SigOperator<A extends Alg> {
  sign: (alg: A, key: JWK<KtyFromAlg<A>, 'Priv'>, m: Uint8Array) => Promise<JWSSignature>;
  verify: (
    alg: A,
    key: JWK<KtyFromAlg<A>, 'Pub'>,
    m: Uint8Array,
    s: JWSSignature
  ) => Promise<boolean>;
}

// --------------------END JWS Digital Signature algorithms --------------------
