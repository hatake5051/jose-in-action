/**
 * @file interface.ts の実装を集約して jws.ts へ提供する。
 */

import { Alg } from 'iana/alg';
import { isESAlg } from 'jwa/sec3/es/alg';
import { ESSigOperator } from 'jwa/sec3/es/impl';
import { isHSAlg } from 'jwa/sec3/hmac/alg';
import { HMACOperator } from 'jwa/sec3/hmac/impl';
import { isPSAlg, isRSAlg } from 'jwa/sec3/rsa/alg';
import { RSASigOperator } from 'jwa/sec3/rsa/impl';
import { JWSOpeMode, MACOperator, SigOperator } from 'jws/interface';

export { JWSOpeModeFromAlg, newSigOperator, newMacOperator };

const isSigAlg = [isRSAlg, isPSAlg, isESAlg] as const;
const isMACAlg = [isHSAlg] as const;

function JWSOpeModeFromAlg(alg: Alg<'JWS'>): JWSOpeMode {
  if (isSigAlg.some((f) => f(alg))) return 'Sig';
  if (isMACAlg.some((f) => f(alg))) return 'MAC';
  if (alg === 'none') return 'None';
  throw new TypeError(`${alg} の実装がない`);
}

/**
 * 署名アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newSigOperator<A extends Alg<'JWS'>>(alg: A): SigOperator<A> {
  if (isRSAlg(alg) || isPSAlg(alg)) return RSASigOperator as SigOperator<A>;
  if (isESAlg(alg)) return ESSigOperator as SigOperator<A>;
  throw new TypeError(`SigOperator<${alg}> は実装されていない`);
}

/**
 * MAC アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newMacOperator<A extends Alg<'JWS'>>(alg: A): MACOperator<A> {
  if (isHSAlg(alg)) return HMACOperator as MACOperator<A>;
  throw TypeError(`MacOperator<${alg}> は実装されていない`);
}
