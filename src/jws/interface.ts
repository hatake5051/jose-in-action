import { Alg, KtyFromAlg } from 'iana/alg';
import { JWK } from 'jwk';
import { JWSSignature } from './type';

/**
 * JWS の JWS Signature 生成 operation の種類を列挙する
 * MAC によるものと、デジタル署名によるものと、署名しないものの３つがある。
 */
export type JWSOpeMode = typeof JWSOpeModeList[number];
export const JWSOpeModeList = ['MAC', 'Sig', 'None'] as const;

/**
 * MAC アルゴリズムのインターフェースを定義する。
 */
export interface MACOperator<A extends Alg<'JWS'>> {
  mac: (alg: A, key: JWK<KtyFromAlg<A>>, m: Uint8Array) => Promise<JWSSignature>;
  verify: (alg: A, key: JWK<KtyFromAlg<A>>, m: Uint8Array, mac: JWSSignature) => Promise<boolean>;
}

/**
 * 署名アルゴリズムのインターフェースを定義する。
 */
export interface SigOperator<A extends Alg<'JWS'>> {
  sign: (alg: A, key: JWK<KtyFromAlg<A>, 'Priv'>, m: Uint8Array) => Promise<JWSSignature>;
  verify: (
    alg: A,
    key: JWK<KtyFromAlg<A>, 'Pub'>,
    m: Uint8Array,
    s: JWSSignature
  ) => Promise<boolean>;
}
