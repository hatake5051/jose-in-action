// --------------------BEGIN JWA JWS algorithms --------------------

import { JWSOpeMode } from 'jws/interface';
import { ESAlg, isESAlg } from './es/alg';
import { HSAlg, isHSAlg } from './hmac/alg';
import { isPSAlg, isRSAlg, PSAlg, RSAlg } from './rsa/alg';

export { JWAJWSAlg, isJWAJWSAlg, KtyFromJWAJWSAlg, ktyFromJWAJWSAlg };

type JWAJWSAlg<M extends JWSOpeMode = JWSOpeMode> = M extends 'MAC'
  ? JWAMACAlg
  : M extends 'Sig'
  ? JWASigAlg
  : M extends 'None'
  ? JWANoneAlg
  : never;

function isJWAJWSAlg<M extends JWSOpeMode>(arg: unknown, m?: M): arg is JWAJWSAlg<M> {
  switch (m) {
    case 'Sig':
      return isJWASigAlg(arg);
    case 'MAC':
      return isJWAMACAlg(arg);
    case 'None':
      return isJWANoneAlg(arg);
    case undefined:
      return isJWASigAlg(arg) || isJWAMACAlg(arg) || isJWANoneAlg(arg);
    default:
      return false;
  }
}

/**
 * JWA で定義されている JWS の署名アルゴリズムを列挙する
 */
type JWASigAlg = RSAlg | PSAlg | ESAlg;

const isJWASigAlg = (arg: unknown): arg is JWASigAlg =>
  isRSAlg(arg) || isPSAlg(arg) || isESAlg(arg);

/**
 * JWS の MAC アルゴリズムを列挙する
 */
type JWAMACAlg = HSAlg;

/**
 * 引数が JWS の MAC アルゴリズムか確認する
 */
const isJWAMACAlg = (arg: unknown): arg is JWAMACAlg => isHSAlg(arg);

/**
 * JWS の Unsecure な none アルゴリズムを列挙する。
 */
type JWANoneAlg = 'none';
const isJWANoneAlg = (arg: unknown): arg is JWANoneAlg => typeof arg === 'string' && arg === 'none';

/**
 * JWS Alg に応じた Kty を返す。
 */
type KtyFromJWAJWSAlg<A extends JWAJWSAlg> = A extends RSAlg | PSAlg
  ? 'RSA'
  : A extends ESAlg
  ? 'EC'
  : A extends HSAlg
  ? 'oct'
  : never;

/**
 * JWS Alg に応じた Kty を返す。
 */
function ktyFromJWAJWSAlg<A extends JWAJWSAlg>(alg: A): KtyFromJWAJWSAlg<A> {
  if (isPSAlg(alg) || isRSAlg(alg)) return 'RSA' as KtyFromJWAJWSAlg<A>;
  if (isESAlg(alg)) return 'EC' as KtyFromJWAJWSAlg<A>;
  if (isHSAlg(alg)) return 'oct' as KtyFromJWAJWSAlg<A>;
  if (isJWANoneAlg(alg)) throw new EvalError('none alg で鍵は使わない');
  throw new TypeError(`${alg} は JWA で定義された JWS の Alg ではない`);
}

// --------------------END JWA JWS algorithms --------------------
