// --------------------BEGIN JWK oct parameters --------------------

import { CommomJWKParams, isCommonJWKParams } from './common';

export { octKey, isOctKey };

/**
 * RFC7518#6.4
 * oct 鍵が持つパラメータを定義する。
 */
type octKeyParams = {
  /**
   * RFC7518#6.4.1
   * Key Value parameter は対称鍵もしくは単一の値を持つ亜k技が含まれる。
   * その鍵の値のオクテット表現の BASE64URL エンコードしたものを値としてもつ。
   */
  k: string;
};

type octKey = CommomJWKParams<'oct'> & octKeyParams;

const isOctKey = (arg: unknown): arg is octKey => {
  if (!isCommonJWKParams(arg) || arg.kty !== 'oct') return false;
  return 'k' in arg;
};

// --------------------END JWK oct parameters --------------------
