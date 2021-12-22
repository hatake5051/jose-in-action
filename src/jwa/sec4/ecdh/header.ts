import { equalsJWK, isJWK, JWK } from 'jwk';
import { isObject } from 'utility';

export {
  ECDH_ESHeaderParams,
  ECDH_ESHeaderParamNames,
  isECDH_ESHeaderParams,
  isPartialECDH_ESHeaderParams,
  equalsECDH_ESHeaderParams,
};

/**
 * RFC7518#4.6.1 Header Parameters Used for ECDH Key Agreement
 * ECDH 鍵合意アルゴリズムのためのヘッダパラメータ
 */
type ECDH_ESHeaderParams = {
  /**
   * RFC8518#4.6.1.1 Ephemeral Public Key Header Parameter
   * 鍵合意アルゴリズム使用される、 originator が作成した公開鍵であり、 JWK で表現。
   * 鍵を表すために必要な最小限の JWK パラメータのみを含むべき (SHOULD)
   */
  epk: JWK<'EC', 'Pub'>;
  // agreement PartyUinfo (the producer に関する情報)
  /**
   * RFC8518#4.6.1.2 Agreement PartyUInfo Header Parameter
   * the producer に関係する情報を含む、 BASE64URL-encoded された文字列。
   * ephemeral key pair を作る側。
   */
  apu?: string;
  /**
   * RFC8518#4.6.1.3 Agreement PartyVInfo Header Parameter
   * the recipient に関係する情報を含む、 BASE64URL-encoded された文字列。
   * static public key を渡す側。
   */
  apv?: string;
};

const ECDH_ESHeaderParamNames = ['epk', 'apu', 'apv'] as const;

const isECDH_ESHeaderParams = (arg: unknown): arg is ECDH_ESHeaderParams =>
  isPartialECDH_ESHeaderParams(arg) && arg.epk != null;

const isPartialECDH_ESHeaderParams = (arg: unknown): arg is Partial<ECDH_ESHeaderParams> =>
  isObject<Partial<ECDH_ESHeaderParams>>(arg) &&
  ECDH_ESHeaderParamNames.every(
    (n) => !arg[n] || (n === 'epk' ? isJWK(arg.epk, 'EC', 'Pub') : typeof arg[n] === 'string')
  );

const equalsECDH_ESHeaderParams = (
  l?: Partial<ECDH_ESHeaderParams>,
  r?: Partial<ECDH_ESHeaderParams>
): boolean => {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  return equalsJWK(l.epk, r.epk) && l.apu === r.apu && l.apv === r.apv;
};
