// --------------------BEGIN JWS MAC algorithms --------------------
import { isJWAMACAlg, JWAMACAlg, KtyFromJWAJWSAlg, newJWAMACOperator } from 'jwa/sec3/alg';
import { JWK } from 'jwk';
import { JWSSignature } from './types';

export { JWSMACAlg, isJWSMACAlg, MACOperator, newMacOperator };

/**
 * JWS の MAC アルゴリズムを列挙する
 */
type JWSMACAlg = JWAMACAlg;

/**
 * 引数が JWS の MAC アルゴリズムか確認する
 */
const isJWSMACAlg = (arg: unknown): arg is JWSMACAlg => isJWAMACAlg(arg);

/**
 * MAC アルゴリズムのインターフェースを定義する。
 */
interface MACOperator<A extends JWSMACAlg> {
  mac: (
    alg: A,
    key: JWK<KtyFromJWSMACAlg<A>, 'Pub' | 'Priv'>,
    m: Uint8Array
  ) => Promise<JWSSignature>;
  verify: (
    alg: A,
    key: JWK<KtyFromJWSMACAlg<A>, 'Pub' | 'Priv'>,
    m: Uint8Array,
    mac: JWSSignature
  ) => Promise<boolean>;
}

/**
 * MAC アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newMacOperator<A extends JWSMACAlg>(alg: A): MACOperator<A> {
  if (isJWAMACAlg(alg)) return newJWAMACOperator(alg) as MACOperator<A>;
  throw TypeError(`MacOperator<${alg}> は実装されていない`);
}

/**
 * JWS の MAC アルゴリズム識別子から Kty を返す
 */
type KtyFromJWSMACAlg<A extends JWSMACAlg> = A extends JWAMACAlg ? KtyFromJWAJWSAlg<A> : never;

// --------------------END JWS MAC algorithms --------------------
