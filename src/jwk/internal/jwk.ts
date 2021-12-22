import { isKty, Kty } from 'iana/kty';
import {
  CommonJWKParams,
  equalsCommonJWKParams,
  exportCommonJWKParams,
  isCommonJWKParams,
} from 'jwk/common';
import {
  equalsJWKECParams,
  equalsJWKOctParams,
  equalsJWKRSAParams,
  exportJWKECPubParams,
  exportJWKRSAPubParams,
  isJWKECParams,
  isJWKOctParams,
  isJWKRSAParams,
  isKeyClass,
  JWKECParams,
  JWKOctParams,
  JWKRSAParams,
  KeyClass,
} from './di';

export { JWK, isJWK, equalsJWK, exportPubJWK };

/**
 * RFC7517#4
 * JSON Web Key は暗号鍵を表現する JSON オブジェクト。
 * Kty がなんであるか、また非対称暗号鍵の場合は公開鍵か秘密鍵かで具体的な型を指定できる
 */
type JWK<K extends Kty = Kty, C extends KeyClass = KeyClass> = CommonJWKParams<K> &
  (K extends 'oct'
    ? JWKOctParams
    : K extends 'RSA'
    ? JWKRSAParams<C>
    : K extends 'EC'
    ? JWKECParams<C>
    : never);

function isJWK<K extends Kty, C extends KeyClass>(
  arg: unknown,
  opt1?: K | C,
  opt2?: C
): arg is JWK<K, C> {
  // options を整理
  let k: Kty | undefined;
  let c: KeyClass | undefined;

  if (isKty(opt1)) k = opt1;
  if (isKeyClass(opt1)) c = opt1;
  if (isKeyClass(opt2)) {
    if (c) throw new TypeError('opt1 で KeyClass を指定しています');
    c = opt2;
  }

  // common jwk parameters を満たしているかチェック
  if (!isCommonJWKParams(arg, k)) return false;

  // kty specific な parameters を満たしているかチェック
  switch (k) {
    case 'oct':
      return isJWKOctParams(arg);
    case 'RSA':
      return isJWKRSAParams(arg, c);
    case 'EC':
      return isJWKECParams(arg, c);
    default:
      return isJWKOctParams(arg) || isJWKRSAParams(arg, c) || isJWKECParams(arg, c);
  }
}

function equalsJWK(l?: Partial<JWK>, r?: Partial<JWK>): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  if (!equalsCommonJWKParams(l, r)) return false;
  if (isJWK(l, 'oct')) {
    return isJWK(r, 'oct') && equalsJWKOctParams(l, r);
  }
  if (isJWK(l, 'RSA')) {
    return isJWK(r, 'RSA') && equalsJWKRSAParams(l, r);
  }
  if (isJWK(l, 'EC')) {
    return isJWK(r, 'EC') && equalsJWKECParams(l, r);
  }
  return true;
}

function exportPubJWK<K extends Kty>(priv: JWK<K, 'Priv'>): JWK<K, 'Pub'> {
  if (isJWK(priv, 'RSA', 'Priv')) {
    const pub = {
      ...exportCommonJWKParams(priv),
      ...exportJWKRSAPubParams(priv),
    };
    if (isJWK<K, 'Pub'>(pub, 'Pub')) return pub;
    throw new TypeError('公開鍵の抽出に失敗');
  }
  if (isJWK(priv, 'EC', 'Priv')) {
    const pub = {
      ...exportCommonJWKParams(priv),
      ...exportJWKECPubParams(priv),
    };
    if (isJWK<K, 'Pub'>(pub, 'Pub')) return pub;
    throw new TypeError('公開鍵の抽出に失敗');
  }
  return priv;
}
