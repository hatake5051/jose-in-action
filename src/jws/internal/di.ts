// --------------------BEGIN JWS dependency injection --------------------

import {
  isJWAMACAlg,
  isJWANoneAlg,
  isJWASigAlg,
  JWAMACAlg,
  JWANoneAlg,
  JWASigAlg,
  ktyFromJWAJWSAlg,
  newJWAMACOperator,
  newJWASigOperator,
} from 'jwa/sec3/alg';
import { MACOperator } from './mac';
import { SigOperator } from './sig';

export {
  JWSSigAlg,
  isJWSSigAlg,
  ktyFromJWSSigAlg,
  newSigOperator,
  JWSMACAlg,
  isJWSMACAlg,
  newMacOperator,
  JWSUnsecureAlg,
  isJWSUnsecureAlg,
};

/**
 * JWS の署名アルゴリズムを列挙する
 */
type JWSSigAlg = JWASigAlg;

/**
 * 引数が JWS の署名アルゴリズム識別子か確認する
 */
const isJWSSigAlg = (arg: unknown): arg is JWSSigAlg => isJWASigAlg(arg);

function ktyFromJWSSigAlg(alg: JWSSigAlg) {
  return ktyFromJWAJWSAlg(alg);
}

/**
 * 署名アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newSigOperator<A extends JWSSigAlg>(alg: A): SigOperator<A> {
  if (isJWASigAlg(alg)) return newJWASigOperator(alg) as SigOperator<A>;
  throw new TypeError(`SigOperator<${alg}> は実装されていない`);
}

/**
 * JWS の MAC アルゴリズムを列挙する
 */
type JWSMACAlg = JWAMACAlg;

/**
 * 引数が JWS の MAC アルゴリズムか確認する
 */
const isJWSMACAlg = (arg: unknown): arg is JWSMACAlg => isJWAMACAlg(arg);

/**
 * MAC アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newMacOperator<A extends JWSMACAlg>(alg: A): MACOperator<A> {
  if (isJWAMACAlg(alg)) return newJWAMACOperator(alg) as MACOperator<A>;
  throw TypeError(`MacOperator<${alg}> は実装されていない`);
}

type JWSUnsecureAlg = JWANoneAlg;
const isJWSUnsecureAlg = (arg: unknown): arg is JWSUnsecureAlg => isJWANoneAlg(arg);

// --------------------END JWS dependency injection --------------------
