// --------------------BEGIN JWS Digital Signature algorithms --------------------
import {
  isJWASigAlg,
  JWASigAlg,
  ktyFromJWAJWSAlg,
  KtyFromJWAJWSAlg,
  newJWASigOperator,
} from 'jwa/sec3/alg';
import { JWK } from 'jwk';
import { JWSSignature } from './types';

export { JWSSigAlg, isJWSSigAlg, SigOperator, newSigOperator, ktyFromJWSSigAlg };

/**
 * JWS の署名アルゴリズムを列挙する
 */
type JWSSigAlg = JWASigAlg;

/**
 * 引数が JWS の署名アルゴリズム識別子か確認する
 */
const isJWSSigAlg = (arg: unknown): arg is JWSSigAlg => isJWASigAlg(arg);

/**
 * 署名アルゴリズムのインターフェースを定義する。
 */
interface SigOperator<A extends JWSSigAlg> {
  sign: (alg: A, key: JWK<KtyFromJWSSigAlg<A>, 'Priv'>, m: Uint8Array) => Promise<JWSSignature>;
  verify: (
    alg: A,
    key: JWK<KtyFromJWSSigAlg<A>, 'Pub'>,
    m: Uint8Array,
    s: JWSSignature
  ) => Promise<boolean>;
}

/**
 * 署名アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newSigOperator<A extends JWSSigAlg>(alg: A): SigOperator<A> {
  if (isJWASigAlg(alg)) return newJWASigOperator(alg) as SigOperator<A>;
  throw new TypeError(`SigOperator<${alg}> は実装されていない`);
}

type KtyFromJWSSigAlg<A extends JWSSigAlg> = A extends JWASigAlg ? KtyFromJWAJWSAlg<A> : never;

function ktyFromJWSSigAlg<A extends JWSSigAlg>(alg: A): KtyFromJWSSigAlg<A> {
  if (isJWASigAlg(alg)) return ktyFromJWAJWSAlg(alg) as KtyFromJWSSigAlg<A>;
  throw new TypeError(`${alg} は JWSSigAlg ではない`);
}

// --------------------END JWS Digital Signature algorithms --------------------
