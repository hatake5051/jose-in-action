// --------------------BEGIN JWK oct parameters --------------------

import { CommomJWKParams, isCommonJWKParams } from './common';

export { octKey, isOctKey };

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

// --------------------END JWK oct parameters --------------------
