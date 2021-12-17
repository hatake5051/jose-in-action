// --------------------BEGIN JWS dependency injection --------------------

import { Alg } from 'iana/alg';
import { isJWAJWSAlg } from 'jwa/sec3/alg';
import { newJWAMACOperator, newJWASigOperator } from 'jwa/sec3/impl';
import { JWSOpeMode, JWSOpeModeList, MACOperator, SigOperator } from 'jws/interface';

export { newSigOperator, newMacOperator };

export function JWSOpeModeFromAlg(alg: Alg<'JWS'>): JWSOpeMode {
  const m = JWSOpeModeList.find((m) => isJWAJWSAlg(alg, m));
  if (m) return m;
  throw new TypeError(`${alg} は JWS のものではない`);
}

/**
 * 署名アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newSigOperator<A extends Alg<'JWS'>>(alg: A): SigOperator<A> {
  if (isJWAJWSAlg(alg, 'Sig')) return newJWASigOperator(alg) as SigOperator<A>;
  throw new TypeError(`SigOperator<${alg}> は実装されていない`);
}

/**
 * MAC アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newMacOperator<A extends Alg<'JWS'>>(alg: A): MACOperator<A> {
  if (isJWAJWSAlg(alg, 'MAC')) return newJWAMACOperator(alg) as MACOperator<A>;
  throw TypeError(`MacOperator<${alg}> は実装されていない`);
}

// --------------------END JWS dependency injection --------------------
