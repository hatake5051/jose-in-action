// --------------------BEGIN JWK EC parameters --------------------

import { Crv } from '../../iana';
import { CommomJWKParams } from './common';

export { ECPublicKey, isECPublicKey, ECPrivateKey, isECPrivateKey };

/**
 * EC 公開鍵は JWK 共通パラメータと EC 公開鍵用パラメータからなる
 */
type ECPublicKey = CommomJWKParams<'EC'> & ECPublicKeyParams;

/**
 * 引数が EC公開鍵の JWK 表現か確認する。
 */
const isECPublicKey = (arg: unknown): arg is ECPublicKey => {
  // TODO: RFC7518 Section6.2.1 に基づいて EC 公開鍵チェックの実装
  return false;
};

/**
 * EC 秘密鍵は EC 公開鍵に EC 秘密鍵用パラメータを加えたもの
 */
type ECPrivateKey = ECPublicKey & ECPrivateKeyParams;

/**
 * 引数が EC 秘密鍵の JWK 表現か確認する。
 */
const isECPrivateKey = (arg: unknown): arg is ECPrivateKey => {
  // TODO: RFC7518 Section6.2.2 に基づいて EC 秘密鍵チェックの実装
  return false;
};

/**
 * RFC7518#6.2.1
 * EC 公開鍵が持つパラメータを定義する。
 */
type ECPublicKeyParams = {
  // TODO: RFC7518 Section6.2.1 に基づいて公開鍵パラメータを定義する
};
const ecPublicKeyParams = [
  /* RFC7518 Section6.2.1 に基づいて公開鍵パラメータを列挙する */
];

/**
 * EC 公開鍵パラメータが矛盾した値になってないか確認する
 */
function validECPublicKeyParams(p: ECPublicKeyParams): boolean {
  // TODO: RFC7518 Section6.2.1 に基づいて公開鍵パラメータのチェックを実装
  return false;
}

/**
 * RFC7518#6.2.2
 * EC 秘密鍵が持つパラメータを定義する。
 */
type ECPrivateKeyParams = {
  // TODO: RFC7518 Section6.2.2 に基づいて秘密鍵パラメータを定義する
};

/**
 * EC 秘密鍵パラメータが引数で与えた crv のものか確認する。
 */
function validECPrivateKeyParams(crv: Crv, p: ECPrivateKeyParams): boolean {
  //  TODO: RFC7518 Section6.2.2 に基づいて秘密鍵パラメータのチェックを実装
  return false;
}

// --------------------END JWK EC parameters --------------------
