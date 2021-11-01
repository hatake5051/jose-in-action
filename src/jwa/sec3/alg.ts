// --------------------BEGIN JWA JWS algorithms --------------------

import { MACOperator, SigOperator } from 'jws';
import { ECAlg, ECSigOperator, isECAlg } from './ec';
import { HMACOperator, HSAlg, isHSAlg } from './hmac';
import { isPSAlg, isRSAlg, PSAlg, RSAlg, RSASigOperator } from './rsa';

export {
  JWASigAlg,
  isJWASigAlg,
  newJWASigOperator,
  JWAMACAlg,
  isJWAMACAlg,
  JWANoneAlg,
  isJWANoneAlg,
  newJWAMACOperator,
  KtyFromJWAJWSAlg,
  ktyFromJWAJWSAlg,
};

/**
 * JWA で定義されている JWS の署名アルゴリズムを列挙する
 */
type JWASigAlg = RSAlg | PSAlg | ECAlg;

const isJWASigAlg = (arg: unknown): arg is JWASigAlg =>
  isRSAlg(arg) || isPSAlg(arg) || isECAlg(arg);

/**
 * JWA で定義されている署名アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newJWASigOperator<A extends JWASigAlg>(alg: A): SigOperator<A> {
  if (isRSAlg(alg) || isPSAlg(alg)) return RSASigOperator as SigOperator<A>;
  if (isECAlg(alg)) return ECSigOperator as SigOperator<A>;
  throw new TypeError(`SigOperator<${alg}> は実装されていない`);
}

/**
 * JWS の MAC アルゴリズムを列挙する
 */
type JWAMACAlg = HSAlg;

/**
 * 引数が JWS の MAC アルゴリズムか確認する
 */
const isJWAMACAlg = (arg: unknown): arg is JWAMACAlg => isHSAlg(arg);

/**
 * MAC アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newJWAMACOperator<A extends JWAMACAlg>(alg: A): MACOperator<A> {
  if (isHSAlg(alg)) return HMACOperator as MACOperator<A>;
  throw TypeError(`MacOperator<${alg}> は実装されていない`);
}

/**
 * JWS の Unsecure な none アルゴリズムを列挙する。
 */
type JWANoneAlg = 'none';
const isJWANoneAlg = (arg: unknown): arg is JWANoneAlg => typeof arg === 'string' && arg === 'none';

/**
 * JWS Alg に応じた Kty を返す。
 */
type KtyFromJWAJWSAlg<A extends JWASigAlg | JWAMACAlg | JWANoneAlg> = A extends RSAlg | PSAlg
  ? 'RSA'
  : A extends ECAlg
  ? 'EC'
  : A extends HSAlg
  ? 'oct'
  : never;

/**
 * JWS Alg に応じた Kty を返す。
 */
function ktyFromJWAJWSAlg<A extends JWASigAlg | JWAMACAlg | JWANoneAlg>(
  alg: A
): KtyFromJWAJWSAlg<A> {
  if (isPSAlg(alg) || isRSAlg(alg)) return 'RSA' as KtyFromJWAJWSAlg<A>;
  if (isECAlg(alg)) return 'EC' as KtyFromJWAJWSAlg<A>;
  if (isHSAlg(alg)) return 'oct' as KtyFromJWAJWSAlg<A>;
  if (isJWANoneAlg(alg)) throw new EvalError('none alg で鍵は使わない');
  throw new TypeError(`${alg} は JWA で定義された JWS の Alg ではない`);
}

// --------------------END JWA JWS algorithms --------------------
