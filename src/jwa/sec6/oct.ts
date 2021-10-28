// --------------------BEGIN JWA symmetric keys --------------------

import { CommomJWKParams, equalsCommonJWKParams, isCommonJWKParams } from '../../jwk/common';

export { octKey, isOctKey, equalsOctKey };

/**
 * 対称鍵は JWK 共通パラメータと共通鍵用パラメータからなる
 */
type octKey = CommomJWKParams<'oct'> & octKeyParams;

/**
 * 引数が対称鍵か確認する。
 * kty == oct で k をパラメータとして持つか確認する。
 */
const isOctKey = (arg: unknown): arg is octKey => {
  if (!isCommonJWKParams(arg) || arg.kty !== 'oct') return false;
  return 'k' in arg;
};

function equalsOctKey(l?: octKey, r?: octKey): boolean {
  if (!equalsCommonJWKParams(l, r)) return false;
  return l?.k === r?.k;
}

/**
 * RFC7518#6.4
 * oct 鍵が持つパラメータを定義する。
 */
type octKeyParams = {
  /**
   * RFC7518#6.4.1
   * Key Value parameter は対称鍵もしくは単一の値を持つ鍵が含まれる。
   * その鍵の値のオクテット表現の BASE64URL エンコードしたものを値としてもつ。
   */
  k: string;
};

// --------------------END JWA symmetric keys --------------------
