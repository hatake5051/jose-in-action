// --------------------BEGIN JWA JWK definition --------------------

import {
  ECPrivateKey,
  ECPublicKey,
  equalsECPrivateKey,
  equalsECPublicKey,
  exportECPublicKey,
  isECPrivateKey,
  isECPublicKey,
} from './ec';
import { JWAKty } from './kty';
import { equalsOctKey, isOctKey, octKey } from './oct';
import {
  equalsRSAPrivateKey,
  equalsRSAPublicKey,
  exportRSAPublicKey,
  isRSAPrivateKey,
  isRSAPublicKey,
  RSAPrivateKey,
  RSAPublicKey,
} from './rsa';

export { JWAJWK, isJWAJWK, equalsJWAJWK, exportJWAPublicKey };

/**
 * JWA で定義された JWK を表現する。
 * K に Kty を指定することで具体的な JWK の型を指定できる。
 * K が RSA か EC の場合は A に Pub か Priv のどちらかを指定することで公開鍵か秘密鍵かの型も指定できる。
 */
type JWAJWK<K extends JWAKty = JWAKty, A extends 'Pub' | 'Priv' = 'Pub' | 'Priv'> = K extends 'oct'
  ? octKey
  : K extends 'EC'
  ? A extends 'Pub'
    ? ECPublicKey
    : A extends 'Priv'
    ? ECPrivateKey
    : ECPublicKey | ECPrivateKey
  : K extends 'RSA'
  ? A extends 'Pub'
    ? RSAPublicKey
    : A extends 'Priv'
    ? RSAPrivateKey
    : RSAPublicKey | RSAPrivateKey
  : never;

function isJWAJWK<K extends JWAKty, A extends 'Pub' | 'Priv'>(
  arg: unknown,
  kty: K,
  asym?: A
): arg is JWAJWK<K, A> {
  switch (kty) {
    case 'oct':
      return isOctKey(arg);
    case 'EC':
      if (asym === undefined) return isECPublicKey(arg) || isECPrivateKey(arg);
      if (asym === 'Pub') return isECPublicKey(arg);
      return isECPrivateKey(arg);
    case 'RSA':
      if (asym === undefined) return isRSAPublicKey(arg) || isRSAPrivateKey(arg);
      if (asym === 'Pub') return isRSAPublicKey(arg);
      return isRSAPrivateKey(arg);
    default:
      return false;
  }
}

function equalsJWAJWK(l?: JWAJWK, r?: JWAJWK): boolean {
  if (l == null && r == null) return true;
  if (l == null || r == null) return false;
  switch (l.kty) {
    case 'oct':
      return r.kty === 'oct' && equalsOctKey(l, r);
    case 'RSA': {
      if (r.kty !== 'RSA') return false;
      if (isRSAPrivateKey(l)) {
        if (isRSAPrivateKey(r)) return equalsRSAPrivateKey(l, r);
        return false;
      }
      if (isRSAPrivateKey(r)) return false;
      return equalsRSAPublicKey(l, r);
    }
    case 'EC': {
      if (r.kty !== 'EC') return false;
      if (isECPrivateKey(l)) {
        if (isECPrivateKey(r)) return equalsECPrivateKey(l, r);
        return false;
      }
      if (isECPrivateKey(r)) return false;
      return equalsECPublicKey(l, r);
    }
  }
}

/**
 * 秘密鍵から公開鍵情報を取り出す。
 */
function exportJWAPublicKey<K extends 'RSA' | 'EC'>(priv: JWAJWK<K, 'Priv'>): JWAJWK<K, 'Pub'> {
  switch (priv.kty) {
    case 'RSA':
      return exportRSAPublicKey(priv) as JWAJWK<K, 'Pub'>;
    case 'EC':
      return exportECPublicKey(priv) as JWAJWK<K, 'Pub'>;
  }
}

// --------------------END JWA JWK definition --------------------
