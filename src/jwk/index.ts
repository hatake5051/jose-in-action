import { Kty, KtyAsym } from '../iana';
import { CommomJWKParams, isCommonJWKParams } from './internal/common';
import {
  ECPrivateKey,
  ECPublicKey,
  isECPrivateKey,
  isECPublicKey,
} from './internal/ec';
import { isOctKey, octKey } from './internal/oct';
import {
  isRSAPrivateKey,
  isRSAPublicKey,
  RSAPrivateKey,
  RSAPublicKey,
} from './internal/rsa';

export {
  JWK,
  JWKSym,
  JWKPriv,
  JWKPub,
  JWKSet,
  isJWKSet,
  isJWK,
  isJWKSym,
  isJWKPub,
  isJWKPriv,
};

/**
 * RFC7517#4
 * JSON Web Key は暗号鍵を表現する JSON オブジェクト。
 */
type JWK<K extends Kty> = CommomJWKParams<K>;

const isJWK = (arg: unknown): arg is JWK<Kty> => isCommonJWKParams(arg);

type JWKSym = octKey;

const isJWKSym = (arg: unknown): arg is JWKSym => isOctKey(arg);

type JWKPub<K extends KtyAsym> = K extends 'EC'
  ? ECPublicKey
  : K extends 'RSA'
  ? RSAPublicKey
  : never;

const isJWKPub = <K extends KtyAsym>(
  kty: K,
  arg: unknown
): arg is JWKPub<K> => {
  if (!isJWK(arg)) return false;
  if (kty !== arg.kty) return false;
  switch (arg.kty) {
    case 'EC':
      return isECPublicKey(arg);
    case 'RSA':
      return isRSAPublicKey(arg);
  }
};

type JWKPriv<K extends KtyAsym> = K extends 'EC'
  ? ECPrivateKey
  : K extends 'RSA'
  ? RSAPrivateKey
  : never;

const isJWKPriv = <K extends KtyAsym>(
  kty: K,
  arg: unknown
): arg is JWKPriv<K> => {
  if (!isJWK(arg)) return false;
  if (kty !== arg.kty) return false;
  switch (arg.kty) {
    case 'EC':
      return isECPrivateKey(arg);
    case 'RSA':
      return isRSAPrivateKey(arg);
  }
};

/**
 * RFC7517#5
 * JWK Set は複数の JWK を表現する JSON オブジェクトである。
 */
type JWKSet = {
  /**
   * RFC7517#5.1
   * keys parameter は JWK の配列を値としてもつ。
   * デフォルトでは、 JWK の順序は鍵の優先順位を表していないが、アプリケーションによっては持たせても良い。
   */
  keys: JWK<Kty>[];
};

const isJWKSet = (arg: unknown): arg is JWKSet => {
  if (typeof arg !== 'object') return false;
  if (arg == null) return false;
  return 'keys' in arg && Array.isArray((arg as JWKSet).keys);
};
