import { isObject } from 'utility';

export {
  AGCMKWHeaderParams,
  AGCMKWHeaderParamNames,
  isPartialAGCMKWHeaderParams,
  isAGCMKWHeaderParams,
  equalsAGCMKWHeaderParams,
};

/**
 * RFC7518#4.7.1 AES GCM Key Encryption で使用されるヘッダーパラメータ
 */
type AGCMKWHeaderParams = {
  /**
   * Initialization Vector Parameter はキー暗号化に使用される 96 bit の iv を base64url-encode した文字列
   */
  iv: string;
  /**
   * Authentication Tag Parameter はキー暗号化の結果の認証タグを base64url-encode した文字列
   */
  tag: string;
};

const AGCMKWHeaderParamNames = ['iv', 'tag'] as const;

const isPartialAGCMKWHeaderParams = (arg: unknown): arg is Partial<AGCMKWHeaderParams> =>
  isObject<Partial<AGCMKWHeaderParams>>(arg) &&
  AGCMKWHeaderParamNames.every((n) => !arg[n] || typeof arg[n] === 'string');

const isAGCMKWHeaderParams = (arg: unknown): arg is AGCMKWHeaderParams =>
  isPartialAGCMKWHeaderParams(arg) && arg.iv != null && arg.tag != null;

function equalsAGCMKWHeaderParams(
  l?: Partial<AGCMKWHeaderParams>,
  r?: Partial<AGCMKWHeaderParams>
): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  return l.iv === r.iv && l.tag === r.tag;
}
