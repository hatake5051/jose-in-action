import { MACOperator, SigOperator } from 'jws/interface';
import { JWAMACAlg, JWASigAlg } from './alg';
import { isESAlg } from './es/alg';
import { ESSigOperator } from './es/impl';
import { isHSAlg } from './hmac/alg';
import { HMACOperator } from './hmac/impl';
import { isPSAlg, isRSAlg } from './rsa/alg';
import { RSASigOperator } from './rsa/impl';

export { newJWASigOperator, newJWAMACOperator };

/**
 * JWA で定義されている署名アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newJWASigOperator<A extends JWASigAlg>(alg: A): SigOperator<A> {
  if (isRSAlg(alg) || isPSAlg(alg)) return RSASigOperator as SigOperator<A>;
  if (isESAlg(alg)) return ESSigOperator as SigOperator<A>;
  throw new TypeError(`SigOperator<${alg}> は実装されていない`);
}

/**
 * MAC アルゴリズム識別子(alg) に応じたアルゴリズムの実装を返す関数
 */
function newJWAMACOperator<A extends JWAMACAlg>(alg: A): MACOperator<A> {
  if (isHSAlg(alg)) return HMACOperator as MACOperator<A>;
  throw TypeError(`MacOperator<${alg}> は実装されていない`);
}
