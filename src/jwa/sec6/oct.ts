// --------------------BEGIN JWA symmetric keys --------------------

import { isObject } from 'utility';

export { JWAOctKeyParams, isJWAOctKeyParams, equalsJWAOctKeyParams };

/**
 * RFC7518#6.4
 * oct 鍵が持つパラメータを定義する。
 */
type JWAOctKeyParams = {
  /**
   * RFC7518#6.4.1
   * Key Value parameter は対称鍵もしくは単一の値を持つ鍵が含まれる。
   * その鍵の値のオクテット表現の BASE64URL エンコードしたものを値としてもつ。
   */
  k: string;
};
const JWAOctKeyParamNames = ['k'] as const;

const isPartialJWAOctKeyParams = (arg: unknown): arg is Partial<JWAOctKeyParams> =>
  isObject<JWAOctKeyParams>(arg) && (arg.k == null || typeof arg.k === 'string');

const isJWAOctKeyParams = (arg: unknown): arg is JWAOctKeyParams =>
  isPartialJWAOctKeyParams(arg) && arg.k != null;

function equalsJWAOctKeyParams(
  l?: Partial<JWAOctKeyParams>,
  r?: Partial<JWAOctKeyParams>
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  return l.k === r.k;
}

// --------------------END JWA symmetric keys --------------------
