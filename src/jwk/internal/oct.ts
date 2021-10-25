// --------------------BEGIN JWK oct parameters --------------------

import { CommomJWKParams } from './common';

export { octKey, isOctKey };

/**
 * 対称鍵は JWK 共通パラメータと共通鍵用パラメータからなる
 */
type octKey = CommomJWKParams<'oct'> & octKeyParams;

/**
 * 引数が対称鍵か確認する。
 */
const isOctKey = (arg: unknown): arg is octKey => {
  // TODO: RFC7518 Section6.4 に基づいて対称鍵のチェックを実装
  return false;
};

/**
 * RFC7518#6.4
 * oct 鍵が持つパラメータを定義する。
 */
type octKeyParams = {
  // TODO: RFC7518 Section6.4 に基づいて対称鍵のパラメータを定義する
};

// --------------------END JWK oct parameters --------------------
